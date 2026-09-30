REPORT ztfdir_rfcint_to_spool_csv
  NO STANDARD PAGE HEADING
  LINE-SIZE 1023.

TABLES: tfdir.

DATA: lt_fms      TYPE STANDARD TABLE OF tfdir-funcname,
      lv_funcname TYPE tfdir-funcname.

DATA: lt_params  TYPE STANDARD TABLE OF rfc_funint,
      ls_param   TYPE rfc_funint,
      lt_res_exc TYPE STANDARD TABLE OF rsexc,
      lv_basxml  TYPE rs38l-basxml_enabled,
      lv_remote  TYPE rs38l-remote,
      lv_utask   TYPE rs38l-utask.

"RTTI for RFC_FUNINT
DATA: lo_td   TYPE REF TO cl_abap_typedescr,
      lo_sd   TYPE REF TO cl_abap_structdescr,
      lt_comp TYPE cl_abap_structdescr=>component_table,
      ls_comp LIKE LINE OF lt_comp.

FIELD-SYMBOLS: <fs_param> TYPE any,
               <fs_field> TYPE any.

DATA: lv_hdr       TYPE string,
      lv_line      TYPE string,
      lv_fm_cnt    TYPE i,
      lv_param_cnt TYPE i,
      lv_fail_cnt  TYPE i.

START-OF-SELECTION.

  SELECT funcname FROM tfdir INTO TABLE lt_fms.
  IF lt_fms IS INITIAL.
    WRITE / 'No entries found in TFDIR.'.
    RETURN.
  ENDIF.

  SORT lt_fms.

  "Header
  lv_hdr = 'FUNCNAME;REMOTE_CALL;UPDATE_TASK;REMOTE_BASXML_SUPPORTED'.

  ASSIGN ls_param TO <fs_param>.
  lo_td = cl_abap_typedescr=>describe_by_data( <fs_param> ).
  lo_sd ?= lo_td.

  IF lo_sd IS NOT INITIAL.
    lt_comp = lo_sd->get_components( ).
    LOOP AT lt_comp INTO ls_comp.
      lv_hdr = lv_hdr && ';' && ls_comp-name.
    ENDLOOP.
  ENDIF.

  WRITE / lv_hdr.

  CLEAR: lv_fm_cnt, lv_param_cnt, lv_fail_cnt.

  LOOP AT lt_fms INTO lv_funcname.
    ADD 1 TO lv_fm_cnt.

    CLEAR: lt_params, lt_res_exc, lv_basxml, lv_remote, lv_utask.

    CALL FUNCTION 'RFC_GET_FUNCTION_INTERFACE'
      EXPORTING
        funcname            = lv_funcname
        language            = sy-langu
        none_unicode_length = space
      IMPORTING
        remote_basxml_supported = lv_basxml
        remote_call             = lv_remote
        update_task             = lv_utask
      TABLES
        params               = lt_params
        resumable_exceptions = lt_res_exc
      EXCEPTIONS
        fu_not_found  = 1
        nametab_fault = 2
        OTHERS        = 3.

    IF sy-subrc <> 0.
      ADD 1 TO lv_fail_cnt.
      CONTINUE.
    ENDIF.

    LOOP AT lt_params INTO ls_param.
      ADD 1 TO lv_param_cnt.

      CLEAR lv_line.

      PERFORM csv_add USING lv_line lv_funcname.
      PERFORM csv_add USING lv_line lv_remote.
      PERFORM csv_add USING lv_line lv_utask.
      PERFORM csv_add USING lv_line lv_basxml.

      ASSIGN ls_param TO <fs_param>.
      lo_td = cl_abap_typedescr=>describe_by_data( <fs_param> ).
      lo_sd ?= lo_td.

      IF lo_sd IS NOT INITIAL.
        lt_comp = lo_sd->get_components( ).
        LOOP AT lt_comp INTO ls_comp.
          ASSIGN COMPONENT ls_comp-name OF STRUCTURE <fs_param> TO <fs_field>.
          IF sy-subrc = 0.
            PERFORM csv_add USING lv_line <fs_field>.
          ELSE.
            PERFORM csv_add USING lv_line ''.
          ENDIF.
        ENDLOOP.
      ENDIF.

      WRITE / lv_line.
    ENDLOOP.
  ENDLOOP.

  "Optional summary as comment (won't break CSV reading if you use comment="#")
  WRITE / |# Summary: FMs={ lv_fm_cnt } Params={ lv_param_cnt } Failures={ lv_fail_cnt }|.

FORM csv_add USING pv_line TYPE string pv_val TYPE any.
  DATA lv_str TYPE string.
  lv_str = pv_val.
  REPLACE ALL OCCURRENCES OF '"' IN lv_str WITH '""'.
  IF pv_line IS INITIAL.
    pv_line = '"' && lv_str && '"'.
  ELSE.
    pv_line = pv_line && ';' && '"' && lv_str && '"'.
  ENDIF.
ENDFORM.