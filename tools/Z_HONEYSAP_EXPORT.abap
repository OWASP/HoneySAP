*&---------------------------------------------------------------------*
*& Report  Z_HONEYSAP_EXPORT
*&
*& Exports two CSV files for use with HoneySAP's RFC Gateway emulation.
*& Uses direct table access (no FM calls) for maximum compatibility.
*&
*& FUPARAREF schema detected on this system (SolMan):
*&   FUNCNAME, R3STATE, PARAMETER, PARAMTYPE (=paramclass!), STRUCTURE,
*&   DEFAULTVAL, REFERENCE, PPOSITION, OPTIONAL, TYPE, CLASS (empty!),
*&   REF_CLASS, LINE_OF, TABLE_OF
*&
*&   PARAMCLASS field: PARAMTYPE has I/E/T/C/X — CLASS is always empty
*&   DEFAULT field:    DEFAULTVAL (e.g. "SPACE" for space default)
*&   Type reference priority: TABLE_OF > STRUCTURE > TYPE
*&   EXID derived: TABLE_OF->'h', STRUCTURE->'u', else DD04L.INTTYPE
*&   Table params (PARAMTYPE='T') always get EXID='h' even if STRUCTURE set
*&   INTLENGTH: DD04L.INTLEN for scalars, 0 for structures/tables
*&              (gateway computes structure size from DDIC catalog)
*&---------------------------------------------------------------------*
REPORT z_honeysap_export.

TABLES: tfdir.

*----------------------------------------------------------------------*
* Selection screen
*----------------------------------------------------------------------*
SELECTION-SCREEN BEGIN OF BLOCK b_out WITH FRAME TITLE TEXT-o01.
PARAMETERS:
  p_rfmf TYPE string DEFAULT '/tmp/honeysap_rfm.csv'  LOWER CASE,
  p_ddif TYPE string DEFAULT '/tmp/honeysap_ddic.csv' LOWER CASE.
SELECTION-SCREEN END OF BLOCK b_out.

SELECTION-SCREEN BEGIN OF BLOCK b_flt WITH FRAME TITLE TEXT-f01.
SELECT-OPTIONS:
  s_func  FOR tfdir-funcname.
PARAMETERS:
  p_remot AS CHECKBOX DEFAULT 'X'.
SELECTION-SCREEN END OF BLOCK b_flt.


*----------------------------------------------------------------------*
* Types
*----------------------------------------------------------------------*
TYPES:
  BEGIN OF ty_tfdir,
    funcname    TYPE funcname,
    remote_flag TYPE c LENGTH 1,
    fmode       TYPE c LENGTH 1,
  END OF ty_tfdir,

  BEGIN OF ty_dd04l_slim,
    rollname TYPE dd04l-rollname,
  END OF ty_dd04l_slim.


*----------------------------------------------------------------------*
* Global data
*----------------------------------------------------------------------*
DATA:
  lt_tfdir_raw   TYPE TABLE OF tfdir,
  lt_tfdir       TYPE TABLE OF ty_tfdir,
  lt_fupararef   TYPE TABLE OF fupararef,
  lt_dd03l       TYPE TABLE OF dd03l,
  lt_dd04l       TYPE TABLE OF dd04l,
  lt_tabnames    TYPE SORTED TABLE OF tabname
                   WITH UNIQUE KEY table_line,
  lt_scalar_refs TYPE SORTED TABLE OF tabname
                   WITH UNIQUE KEY table_line,
  lv_line        TYPE string,
  lv_tabname     TYPE tabname,
  lv_len         TYPE i,
  lv_written     TYPE i,
  lv_param_count TYPE i.

FIELD-SYMBOLS:
  <fs_remote> TYPE any,
  <fs_fmode>  TYPE any,
  <fs_comp>   TYPE any,
  <fs_any>    TYPE any.


*----------------------------------------------------------------------*
* Helper: append one double-quoted semicolon-separated field
*----------------------------------------------------------------------*
FORM append_field USING iv_val TYPE any.
  DATA lv_str TYPE string.
  lv_str = iv_val.
  REPLACE ALL OCCURRENCES OF '"' IN lv_str WITH '""'.
  CONCATENATE lv_line '"' lv_str '"' ';' INTO lv_line.
ENDFORM.


*----------------------------------------------------------------------*
* Helper: find the remote-flag field in TFDIR at runtime
*----------------------------------------------------------------------*
FORM find_remote_field USING    is_row   TYPE tfdir
                       CHANGING cv_fname TYPE string.
  DATA lt_cands TYPE TABLE OF string.
  APPEND 'RFCSCOPE'    TO lt_cands.
  APPEND 'REMOTCALL'   TO lt_cands.
  APPEND 'REMOTE'      TO lt_cands.
  APPEND 'RFCSUPP'     TO lt_cands.
  APPEND 'RFCENABLED'  TO lt_cands.
  APPEND 'REMOTE_CALL' TO lt_cands.
  APPEND 'RFCTYPE'     TO lt_cands.
  CLEAR cv_fname.
  LOOP AT lt_cands INTO DATA(lv_c).
    ASSIGN COMPONENT lv_c OF STRUCTURE is_row TO <fs_remote>.
    IF <fs_remote> IS ASSIGNED.
      cv_fname = lv_c.
      RETURN.
    ENDIF.
  ENDLOOP.
ENDFORM.


*----------------------------------------------------------------------*
* Helper: read one field from a FUPARAREF row by component name.
*         Returns space when the component does not exist.
*----------------------------------------------------------------------*
FORM get_fup USING    is_row   TYPE fupararef
                      iv_name  TYPE string
             CHANGING cv_val   TYPE string.
  CLEAR cv_val.
  ASSIGN COMPONENT iv_name OF STRUCTURE is_row TO <fs_comp>.
  IF <fs_comp> IS ASSIGNED.
    cv_val = <fs_comp>.
  ENDIF.
ENDFORM.


*----------------------------------------------------------------------*
* START-OF-SELECTION
*----------------------------------------------------------------------*
START-OF-SELECTION.

  "--------------------------------------------------------------------
  " 1. Read TFDIR
  "--------------------------------------------------------------------
  SELECT * FROM tfdir
    INTO TABLE lt_tfdir_raw
    WHERE funcname IN s_func.

  IF lt_tfdir_raw IS INITIAL.
    MESSAGE 'No function modules found.' TYPE 'I'.
    RETURN.
  ENDIF.

  DATA lv_remote_fname TYPE string.
  DATA(ls_tfdir_probe) = lt_tfdir_raw[ 1 ].
  PERFORM find_remote_field USING    ls_tfdir_probe
                            CHANGING lv_remote_fname.

  LOOP AT lt_tfdir_raw INTO DATA(ls_raw).
    DATA(ls_t) = VALUE ty_tfdir( funcname = ls_raw-funcname ).
    IF lv_remote_fname IS NOT INITIAL.
      ASSIGN COMPONENT lv_remote_fname OF STRUCTURE ls_raw TO <fs_remote>.
      IF <fs_remote> IS ASSIGNED.
        ls_t-remote_flag = <fs_remote>.
      ENDIF.
    ENDIF.
    ASSIGN COMPONENT 'FMODE' OF STRUCTURE ls_raw TO <fs_fmode>.
    IF <fs_fmode> IS ASSIGNED.
      ls_t-fmode = <fs_fmode>.
    ENDIF.
    IF p_remot = abap_true AND lv_remote_fname IS NOT INITIAL
                            AND ls_t-remote_flag = space.
      CONTINUE.
    ENDIF.
    APPEND ls_t TO lt_tfdir.
  ENDLOOP.

  IF lt_tfdir IS INITIAL.
    MESSAGE 'No remote-enabled function modules found.' TYPE 'I'.
    RETURN.
  ENDIF.

  WRITE: / 'Function modules selected:', lines( lt_tfdir ).

  "--------------------------------------------------------------------
  " 2. Read FUPARAREF
  "--------------------------------------------------------------------
  SELECT * FROM fupararef
    INTO TABLE lt_fupararef
    FOR ALL ENTRIES IN lt_tfdir
    WHERE funcname = lt_tfdir-funcname.

  IF lt_fupararef IS INITIAL.
    MESSAGE 'No rows found in FUPARAREF for selected FMs.' TYPE 'W'.
    RETURN.
  ENDIF.

  "--------------------------------------------------------------------
  " 3. First pass: collect scalar type names for DD04L bulk read
  "--------------------------------------------------------------------
  LOOP AT lt_fupararef INTO DATA(ls_pre).
    DATA: lv_table_of_p TYPE string,
          lv_structure_p TYPE string,
          lv_type_p      TYPE string.
    PERFORM get_fup USING ls_pre 'TABLE_OF'  CHANGING lv_table_of_p.
    PERFORM get_fup USING ls_pre 'STRUCTURE' CHANGING lv_structure_p.
    PERFORM get_fup USING ls_pre 'TYPE'      CHANGING lv_type_p.

    IF lv_table_of_p IS NOT INITIAL.
      INSERT CONV tabname( lv_table_of_p ) INTO TABLE lt_tabnames.
    ELSEIF lv_structure_p IS NOT INITIAL.
      INSERT CONV tabname( lv_structure_p ) INTO TABLE lt_tabnames.
    ELSEIF lv_type_p IS NOT INITIAL.
      INSERT CONV tabname( lv_type_p ) INTO TABLE lt_scalar_refs.
    ENDIF.
  ENDLOOP.

  " Bulk read DD04L for scalar type info (EXID + INTLENGTH)
  IF lt_scalar_refs IS NOT INITIAL.
    SELECT * FROM dd04l
      INTO TABLE lt_dd04l
      FOR ALL ENTRIES IN lt_scalar_refs
      WHERE rollname = lt_scalar_refs-table_line.
    SORT lt_dd04l BY rollname.
    DELETE ADJACENT DUPLICATES FROM lt_dd04l COMPARING rollname.
  ENDIF.

  "--------------------------------------------------------------------
  " 4. Write RFM CSV
  "--------------------------------------------------------------------
  OPEN DATASET p_rfmf FOR OUTPUT IN TEXT MODE ENCODING DEFAULT.
  IF sy-subrc <> 0.
    MESSAGE |Cannot open output file: { p_rfmf }| TYPE 'E'.
    RETURN.
  ENDIF.

  lv_line = 'FUNCNAME;REMOTE_CALL;UPDATE_TASK;REMOTE_BASXML_SUPPORTED;'
         && 'PARAMCLASS;PARAMETER;TABNAME;FIELDNAME;EXID;POSITION;OFFSET;'
         && 'INTLENGTH;DECIMALS;DEFAULT;PARAMTEXT;OPTIONAL'.
  TRANSFER lv_line TO p_rfmf.

  CLEAR lv_param_count.

  LOOP AT lt_fupararef INTO DATA(ls_fup).

    READ TABLE lt_tfdir WITH KEY funcname = ls_fup-funcname
                        INTO DATA(ls_td).
    IF sy-subrc <> 0.
      CONTINUE.
    ENDIF.

    " Read all relevant FUPARAREF fields by component name
    DATA: lv_paramtype  TYPE string,
          lv_parameter  TYPE string,
          lv_table_of   TYPE string,
          lv_structure  TYPE string,
          lv_type_name  TYPE string,
          lv_pposition  TYPE string,
          lv_defaultval TYPE string,
          lv_optional   TYPE string,
          lv_paramtext  TYPE string.

    " PARAMCLASS field name varies by release: PARAMTYPE, CLASS, PARAMKIND, DIRECTION
    PERFORM get_fup USING ls_fup 'PARAMTYPE'  CHANGING lv_paramtype.
    IF lv_paramtype IS INITIAL.
      PERFORM get_fup USING ls_fup 'CLASS'    CHANGING lv_paramtype.
    ENDIF.
    IF lv_paramtype IS INITIAL.
      PERFORM get_fup USING ls_fup 'PARAMKIND' CHANGING lv_paramtype.
    ENDIF.
    PERFORM get_fup USING ls_fup 'PARAMETER'  CHANGING lv_parameter.
    PERFORM get_fup USING ls_fup 'TABLE_OF'   CHANGING lv_table_of.
    PERFORM get_fup USING ls_fup 'STRUCTURE'  CHANGING lv_structure.
    PERFORM get_fup USING ls_fup 'TYPE'       CHANGING lv_type_name.
    PERFORM get_fup USING ls_fup 'PPOSITION'  CHANGING lv_pposition.
    " DEFAULT field name varies: DEFAULTVAL, DFTVAL, DEFAULT_VAL
    PERFORM get_fup USING ls_fup 'DEFAULTVAL' CHANGING lv_defaultval.
    IF lv_defaultval IS INITIAL.
      PERFORM get_fup USING ls_fup 'DFTVAL'   CHANGING lv_defaultval.
    ENDIF.
    PERFORM get_fup USING ls_fup 'OPTIONAL'   CHANGING lv_optional.
    PERFORM get_fup USING ls_fup 'PARAMTEXT'  CHANGING lv_paramtext.

    " Derive TABNAME, EXID, INTLENGTH from type reference fields
    DATA: lv_tabname_out  TYPE string,
          lv_exid_out     TYPE string,
          lv_intlen_out   TYPE string.

    IF lv_table_of IS NOT INITIAL.
      lv_tabname_out = lv_table_of.
      lv_exid_out    = 'h'.
      lv_intlen_out  = '0'.
    ELSEIF lv_structure IS NOT INITIAL.
      lv_tabname_out = lv_structure.
      lv_exid_out    = 'u'.
      lv_intlen_out  = '0'.
    ELSEIF lv_type_name IS NOT INITIAL.
      lv_tabname_out = lv_type_name.
      " Look up scalar type info from DD04L using ASSIGN COMPONENT
      DATA ls_d04 LIKE LINE OF lt_dd04l.
      READ TABLE lt_dd04l WITH KEY rollname = CONV dd04l-rollname( lv_type_name )
                          INTO ls_d04.
      IF sy-subrc = 0.
        " INTTYPE field may be named differently on this release
        ASSIGN COMPONENT 'INTTYPE'   OF STRUCTURE ls_d04 TO <fs_any>.
        IF <fs_any> IS ASSIGNED. lv_exid_out = <fs_any>. ENDIF.
        ASSIGN COMPONENT 'DATATYPE'  OF STRUCTURE ls_d04 TO <fs_any>.
        IF <fs_any> IS ASSIGNED AND lv_exid_out IS INITIAL.
          lv_exid_out = <fs_any>.
        ENDIF.
        " INTLEN field may be named differently on this release
        ASSIGN COMPONENT 'INTLEN'    OF STRUCTURE ls_d04 TO <fs_any>.
        IF <fs_any> IS ASSIGNED. lv_intlen_out = <fs_any>. ENDIF.
        ASSIGN COMPONENT 'LENG'      OF STRUCTURE ls_d04 TO <fs_any>.
        IF <fs_any> IS ASSIGNED AND lv_intlen_out IS INITIAL.
          lv_intlen_out = <fs_any>.
        ENDIF.
      ENDIF.
    ENDIF.

    " Exceptions have no type
    IF lv_paramtype = 'X'.
      CLEAR: lv_tabname_out, lv_exid_out, lv_intlen_out.
    ENDIF.

    " On some systems (SolMan) TABLE parameters store the type in STRUCTURE
    " instead of TABLE_OF, causing EXID='u'.  A TABLE param always needs 'h'.
    IF lv_paramtype = 'T' AND lv_exid_out = 'u'.
      lv_exid_out = 'h'.
    ENDIF.

    " Collect only structure/table types for DDIC export (not scalars)
    IF lv_tabname_out IS NOT INITIAL
       AND ( lv_exid_out = 'h' OR lv_exid_out = 'u' ).
      INSERT CONV tabname( lv_tabname_out ) INTO TABLE lt_tabnames.
    ENDIF.

    CLEAR lv_line.
    PERFORM append_field USING ls_fup-funcname.
    PERFORM append_field USING ls_td-remote_flag.
    PERFORM append_field USING ls_td-fmode.
    PERFORM append_field USING ''.
    PERFORM append_field USING lv_paramtype.
    PERFORM append_field USING lv_parameter.
    PERFORM append_field USING lv_tabname_out.
    PERFORM append_field USING ''.              " FIELDNAME not available
    PERFORM append_field USING lv_exid_out.
    PERFORM append_field USING lv_pposition.
    PERFORM append_field USING ''.              " OFFSET not available
    PERFORM append_field USING lv_intlen_out.
    PERFORM append_field USING ''.              " DECIMALS not available
    PERFORM append_field USING lv_defaultval.
    PERFORM append_field USING lv_paramtext.
    PERFORM append_field USING lv_optional.

    lv_len = strlen( lv_line ) - 1.
    lv_line = lv_line+0(lv_len).
    TRANSFER lv_line TO p_rfmf.
    ADD 1 TO lv_param_count.

  ENDLOOP.

  CLOSE DATASET p_rfmf.
  WRITE: / 'RFM CSV written to', p_rfmf,
         / '  Parameter rows written:', lv_param_count.
  WRITE: / 'Unique types for DDIC:', lines( lt_tabnames ).

  "--------------------------------------------------------------------
  " 5. Resolve table types via DD40L, then read DD03L
  "
  "    Parameters typed as TABLE OF <table_type> give us the table
  "    type name (e.g. /SLOAE/T_MODULE_GENERATE).  Table types are
  "    stored in DD40L with their LINE TYPE in a ROWTYPE-like field.
  "    The actual field definitions are in DD03L for the line type.
  "--------------------------------------------------------------------
  IF lt_tabnames IS INITIAL.
    WRITE: / 'No structure types — skipping DDIC export.'.
    RETURN.
  ENDIF.

  " Resolve table types to their line types via DD40L.
  " lt_name_map records original->resolved so we can write DDIC rows
  " under the ORIGINAL name (what the SDK will query via DDIF).
  TYPES: BEGIN OF ty_name_map,
           original TYPE tabname,
           resolved TYPE tabname,
         END OF ty_name_map.
  DATA: lt_dd40l        TYPE TABLE OF dd40l,
        lt_lookup_names TYPE SORTED TABLE OF tabname
                          WITH UNIQUE KEY table_line,
        lt_name_map     TYPE TABLE OF ty_name_map.

  SELECT * FROM dd40l
    INTO TABLE lt_dd40l
    FOR ALL ENTRIES IN lt_tabnames
    WHERE typename = lt_tabnames-table_line.

  LOOP AT lt_tabnames INTO lv_tabname.
    DATA lv_rowtype TYPE string.
    CLEAR lv_rowtype.

    " Find the matching DD40L row and read its line type field
    LOOP AT lt_dd40l INTO DATA(ls_dd40).
      ASSIGN COMPONENT 'TYPENAME' OF STRUCTURE ls_dd40 TO <fs_any>.
      IF <fs_any> IS ASSIGNED AND <fs_any> = lv_tabname.
        " Try common field names for the line type
        ASSIGN COMPONENT 'ROWTYPE'  OF STRUCTURE ls_dd40 TO <fs_any>.
        IF <fs_any> IS ASSIGNED AND <fs_any> IS NOT INITIAL.
          lv_rowtype = <fs_any>.
          EXIT.
        ENDIF.
        ASSIGN COMPONENT 'LINETYPE' OF STRUCTURE ls_dd40 TO <fs_any>.
        IF <fs_any> IS ASSIGNED AND <fs_any> IS NOT INITIAL.
          lv_rowtype = <fs_any>.
          EXIT.
        ENDIF.
      ENDIF.
    ENDLOOP.

    IF lv_rowtype IS NOT INITIAL.
      " Table type resolved to its line structure
      INSERT CONV tabname( lv_rowtype ) INTO TABLE lt_lookup_names.
      APPEND VALUE ty_name_map(
        original = lv_tabname
        resolved = CONV #( lv_rowtype ) ) TO lt_name_map.
    ELSE.
      " No DD40L entry — treat as direct structure; name maps to itself
      INSERT lv_tabname INTO TABLE lt_lookup_names.
      APPEND VALUE ty_name_map(
        original = lv_tabname
        resolved = lv_tabname ) TO lt_name_map.
    ENDIF.
  ENDLOOP.

  SELECT * FROM dd03l
    INTO TABLE lt_dd03l
    FOR ALL ENTRIES IN lt_lookup_names
    WHERE tabname = lt_lookup_names-table_line.

  SORT lt_dd03l BY tabname fieldname as4local DESCENDING.
  DELETE ADJACENT DUPLICATES FROM lt_dd03l COMPARING tabname fieldname.
  WRITE: / 'DD03L rows after resolution:', lines( lt_dd03l ).

  "--------------------------------------------------------------------
  " 6. Write DDIC CSV
  "--------------------------------------------------------------------
  OPEN DATASET p_ddif FOR OUTPUT IN TEXT MODE ENCODING DEFAULT.
  IF sy-subrc <> 0.
    MESSAGE |Cannot open output file: { p_ddif }| TYPE 'E'.
    RETURN.
  ENDIF.

  lv_line = 'TABNAME;FIELDNAME;POSITION;KEYFLAG;DATATYPE;LENG;OUTPUTLEN;'
         && 'DECIMALS;INTTYPE;INTLEN;OFFSET;OFFSET_UNI;ROLLNAME;REPTEXT'.
  TRANSFER lv_line TO p_ddif.

  CLEAR lv_written.

  LOOP AT lt_dd03l INTO DATA(ls_d).
    IF ls_d-adminfield <> 0.
      CONTINUE.
    ENDIF.

    DATA lv_reptext TYPE string.
    CLEAR lv_reptext.
    IF ls_d-rollname IS NOT INITIAL.
      SELECT SINGLE ddtext FROM dd04t
        INTO lv_reptext
        WHERE rollname   = ls_d-rollname
          AND ddlanguage = sy-langu
          AND as4local   = 'A'.
    ENDIF.

    DATA: lv_outputlen  TYPE string,
          lv_d_offset   TYPE string,
          lv_offset_uni TYPE string.
    CLEAR: lv_outputlen, lv_d_offset, lv_offset_uni.

    ASSIGN COMPONENT 'OUTPUTLEN' OF STRUCTURE ls_d TO <fs_any>.
    IF <fs_any> IS ASSIGNED.
      lv_outputlen = <fs_any>.
    ELSE.
      ASSIGN COMPONENT 'OUTPUTSTYLE' OF STRUCTURE ls_d TO <fs_any>.
      IF <fs_any> IS ASSIGNED.
        lv_outputlen = <fs_any>.
      ENDIF.
    ENDIF.

    ASSIGN COMPONENT 'OFFSET' OF STRUCTURE ls_d TO <fs_any>.
    IF <fs_any> IS ASSIGNED.
      lv_d_offset = <fs_any>.
    ENDIF.

    ASSIGN COMPONENT 'OFFSET_UNI' OF STRUCTURE ls_d TO <fs_any>.
    IF <fs_any> IS ASSIGNED.
      lv_offset_uni = <fs_any>.
    ENDIF.

    " Use the original table type name (what the SDK queries via DDIF),
    " not the resolved line structure name stored in DD03L.
    DATA lv_out_tabname TYPE tabname.
    READ TABLE lt_name_map WITH KEY resolved = ls_d-tabname
                           INTO DATA(ls_map).
    IF sy-subrc = 0.
      lv_out_tabname = ls_map-original.
    ELSE.
      lv_out_tabname = ls_d-tabname.
    ENDIF.

    CLEAR lv_line.
    PERFORM append_field USING lv_out_tabname.
    PERFORM append_field USING ls_d-fieldname.
    PERFORM append_field USING ls_d-position.
    PERFORM append_field USING ls_d-keyflag.
    PERFORM append_field USING ls_d-datatype.
    PERFORM append_field USING ls_d-leng.
    PERFORM append_field USING lv_outputlen.
    PERFORM append_field USING ls_d-decimals.
    PERFORM append_field USING ls_d-inttype.
    PERFORM append_field USING ls_d-intlen.
    PERFORM append_field USING lv_d_offset.
    PERFORM append_field USING lv_offset_uni.
    PERFORM append_field USING ls_d-rollname.
    PERFORM append_field USING lv_reptext.

    lv_len = strlen( lv_line ) - 1.
    lv_line = lv_line+0(lv_len).
    TRANSFER lv_line TO p_ddif.
    ADD 1 TO lv_written.

  ENDLOOP.

  CLOSE DATASET p_ddif.
  WRITE: / 'DDIC CSV written to', p_ddif,
         / '  Structures resolved:', lines( lt_tabnames ),
         / '  Field rows written: ', lv_written.
