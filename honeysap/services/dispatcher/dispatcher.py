# ===========
# HoneySAP - SAP low-interaction honeypot
#
# Copyright (C) 2015 by Martin Gallo, SecureAuth Corporation
#
# The library was designed and developed by Martin Gallo from
# SecureAuth Corporation's Labs team.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# ==============

# Standard imports
import string
from socket import error
from binascii import unhexlify
from random import SystemRandom
# External imports
from scapy.packet import bind_layers

from pysap.SAPDiag import (SAPDiag, SAPDiagDP, SAPDiagItem)
from pysap.SAPNI import (SAPNIServerThreaded, SAPNIServerHandler, SAPNIClient)
from pysap.SAPDiagItems import (support_data_sapnw_702, SAPDiagAreaSize,
                                SAPDiagMenuEntries, SAPDiagMenuEntry,
                                SAPDiagDyntAtom, SAPDiagDyntAtomItem,
                                SAPDiagStep, SAPDiagSES)
# Custom imports
from honeysap.core.logger import Loggeable
from honeysap.core.service import BaseTCPService


bind_layers(SAPDiagDP, SAPDiag,)
bind_layers(SAPDiag, SAPDiagItem,)
bind_layers(SAPDiagItem, SAPDiagItem,)


class SAPDispatcherClient(Loggeable, SAPNIClient):

    terminal = None
    init = False


class SAPDispatcherServerHandler(Loggeable, SAPNIServerHandler):

    @property
    def hostname(self):
        return self.config.get("hostname", "sapnw702")

    @property
    def client_no(self):
        return self.config.get("client_no", "001")

    @property
    def sid(self):
        return self.config.get("sid", "PRD")

    @property
    def session_title(self):
        return self.config.get("session_title", "SAP Netweaver Server")

    @property
    def database_version(self):
        return self.config.get("database_version", "702")

    @property
    def kernel_version(self):
        return self.config.get("kernel_version", "7200")

    @property
    def kernel_patch_level(self):
        return self.config.get("kernel_patch_level", "70")

    def __init__(self, request, client_address, server):
        """Initialization"""
        self.config = server.config
        client_ip, client_port = client_address
        server_ip, server_port = server.server_address
        self.session = server.session_manager.get_session("dispatcher",
                                                          client_ip,
                                                          client_port,
                                                          server_ip,
                                                          server_port)
        SAPNIServerHandler.__init__(self, request, client_address, server)

    def handle_data(self):
        """Handles a received packet"""
        self.session.add_event("Received packet", request=str(self.packet))

        print self.server, self.server.clients

        if self.client_address in self.server.clients and self.server.clients[self.client_address].init:
            self.logger.debug("Already initialized client %s" % str(self.client_address))
            self.handle_msg()
        else:
            self.logger.debug("Uninitialized client %s" % str(self.client_address))
            self.handle_init()

    def handle_init(self):
        self.logger.debug("Handling init")
        # For initialization we need to decode the packet as SAPDiagDP
        self.packet.decode_payload_as(SAPDiagDP)
        if SAPDiagDP in self.packet:
            self.context_id = self.make_context_id()
            self.server.clients[self.client_address].init = True
            self.server.clients[self.client_address].terminal = self.packet[SAPDiagDP].terminal
            self.server.clients[self.client_address].context_id = self.context_id
            login_screen = SAPDiag(compress=0, message=self.make_login_screen())
            self.request.send(login_screen)
            self.session.add_event("Initialization request received", data={"terminal": self.packet[SAPDiagDP].terminal},
                                   request=str(self.packet), response=str(login_screen))
        else:
            self.logger.debug("Error during initialization of client %s" % str(self.client_address))
            self.logoff()

    def handle_msg(self):
        self.logger.debug("Received message from client %s" % str(self.client_address))
        diag = self.packet[SAPDiag]

        # Handle exit transaction (OK CODE = /i)
        if len(diag.get_item("APPL", "VARINFO", "OKCODE")) > 0 and diag.get_item("APPL", "VARINFO", "OKCODE")[0].item_value == "/i":
            self.logger.debug("Windows closed by the client %s" % str(self.client_address))
            self.session.add_event("Windows closed by the client")
            self.logoff()

        # Handle events (UI EVENT SOURCE)
        elif len(diag.get_item("APPL", "UI_EVENT", "UI_EVENT_SOURCE")) > 0:
            self.logger.debug("UI Event sent by the client %s" % str(self.client_address))
            ui_event_source = diag.get_item("APPL", "UI_EVENT", "UI_EVENT_SOURCE")[0].item_value

            # Handle function key
            if ui_event_source.valid_functionkey_data:
                # Handle logoff event
                if ui_event_source.event_type == 7 and ui_event_source.control_type == 10 and ui_event_source.event_data == 15:
                    self.logger.debug("Logoff sent by the client %s" % str(self.client_address))
                    self.session.add_event("Logoff sent the client")
                    self.logoff()

                # Handle enter event
                elif ui_event_source.event_type == 7 and ui_event_source.control_type == 10 and ui_event_source.event_data == 0:
                    self.logger.debug("Enter sent by the client %s" % str(self.client_address))
                    self.session.add_event("Enter sent the client")

            # Handle menu option
            elif ui_event_source.valid_menu_pos:
                self.logger.debug("Menu event sent by the client %s" % str(self.client_address))
                self.session.add_event("Menu event sent the client")

            else:
                self.logger.debug("Other event sent by the client %s" % str(self.client_address))
                self.session.add_event("Other event sent the client")

        # Handle login request (DYNT Atom == \x00)
        atoms = diag.get_item(["APPL", "APPL4"], "DYNT", "DYNT_ATOM")
        if len(atoms) > 0:
            self.logger.debug("Login request sent by the client %s" % str(self.client_address))
            inputs = []
            for atom in [atom for atom_item in atoms for atom in atom_item.item_value.items]:
                if atom.etype in [121, 122, 123, 130, 131, 132]:
                    text = atom.field1_text or atom.field2_text
                    text = text.strip()
                    if atom.attr_DIAG_BSD_INVISIBLE and len(text) > 0:
                        # If the invisible flag was set, we're probably
                        # dealing with a password field
                        self.logger.debug("Password field: %s" % (text))
                    else:
                        self.logger.debug("Regular field:%s" % (text))
                    inputs.append(text)
            self.session.add_event("Login request sent the client", data={"inputs": inputs})

            response = SAPDiag(compress=1, message=self.make_error_screen("E: Unable to process your request, try later"))
            self.logger.debug("Sending error message to client %s" % str(self.client_address))
            self.session.add_event("Error message sent to the client", response=str(response))
            self.request.send(response)

        # Otherwise we send an error message
        else:
            self.logger.debug("Sending error message to client %s" % str(self.client_address))
            try:
                response = SAPDiag(compress=0, message=self.make_error_screen("E: Unable to process your request, try later"))
                self.session.add_event("Error message sent to the client", response=str(response))
                self.request.send(response)
            except error:
                pass

    def make_login_screen(self):
        self.logger.debug("Making login screen for %s" % str(self.client_address))
        return [SAPDiagItem(item_value='\x00\x00\x10\x0e\x014110\x00UTF8\x00', item_type=16, item_id=6, item_sid=35),
                SAPDiagItem(item_value='\x00\x00\x10\x07\x024103\x00UnicodeLittleUnmarked\x00', item_type=16, item_id=6, item_sid=39),
                SAPDiagItem(item_value=self.context_id, item_type=16, item_id=6, item_sid=33),
                SAPDiagItem(item_value=self.sid, item_type=16, item_id=6, item_sid=2),
                SAPDiagItem(item_value=self.hostname, item_type=16, item_id=6, item_sid=3),
                SAPDiagItem(item_value='/m', item_type=16, item_id=6, item_sid=25),
                SAPDiagItem(item_value='\x00\x00', item_type=16, item_id=6, item_sid=1),
                SAPDiagItem(item_value='\x00\x00', item_type=16, item_id=6, item_sid=10),
                SAPDiagItem(item_value="\x01%s\x01" % unhexlify(self.context_id), item_type=16, item_id=6, item_sid=31),
                SAPDiagItem(item_value='TRADESHOW\x00', item_type=16, item_id=6, item_sid=37),
                SAPDiagItem(item_value=self.make_kernel_version(), item_type=16, item_id=6, item_sid=41),
                SAPDiagItem(item_value='\x00\x03\xd0\x90', item_type=16, item_id=6, item_sid=22),
                SAPDiagItem(item_value=SAPDiagStep(step=1), item_type=16, item_id=4, item_sid=38),
                SAPDiagItem(item_value='\x0100\x00&0\x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0101\x00&F\x001 \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0102\x00&F\x002 \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0103\x00&F\x003 \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0104\x00&F\x004 \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0105\x00&F\x005 \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0106\x00&F\x006 \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0107\x00&F\x007 \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0108\x00&F\x008 \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0109\x00&F\x009 \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0110\x00&F\x0010\x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0111\x00&C\x00S \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0211\x00&F\x0011\x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0112\x00&F\x0012\x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0212\x00&E\x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0113\x00&S\x00&F\x001 \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0114\x00&S\x00&F\x002 \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0115\x00&S\x00&F\x003 \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0116\x00&S\x00&F\x004 \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0117\x00&S\x00&F\x005 \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0118\x00&S\x00&F\x006 \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0119\x00&S\x00&F\x007 \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0120\x00&S\x00&F\x008 \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0121\x00&S\x00&F\x009 \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0122\x00&S\x00&C\x000 \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0123\x00&S\x00&F\x0011\x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0124\x00&S\x00&F\x0012\x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0125\x00&A\x00&S\x00&F\x001 \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0126\x00&A\x00&S\x00&F\x002 \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0127\x00&A\x00&S\x00&F\x003 \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0128\x00&A\x00&S\x00&F\x004 \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0129\x00&A\x00&S\x00&F\x005 \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0130\x00&A\x00&S\x00&F\x006 \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0131\x00&A\x00&S\x00&F\x007 \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0132\x00&A\x00&S\x00&F\x008 \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0133\x00&A\x00&S\x00&F\x009 \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0134\x00&A\x00&S\x00&F\x0010\x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0135\x00&A\x00&S\x00&F\x0011\x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0136\x00&A\x00&S\x00&F\x0012\x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0137\x00&C\x00&S\x00&F\x001 \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0138\x00&C\x00&S\x00&F\x002 \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0139\x00&C\x00&S\x00&F\x003 \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0140\x00&C\x00&S\x00&F\x004 \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0141\x00&C\x00&S\x00&F\x005 \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0142\x00&C\x00&S\x00&F\x006 \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0143\x00&C\x00&S\x00&F\x007 \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0144\x00&C\x00&S\x00&F\x008 \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0145\x00&C\x00&S\x00&F\x009 \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0146\x00&C\x00&S\x00&F\x0010\x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0147\x00&C\x00&S\x00&F\x0011\x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0148\x00&C\x00&S\x00&F\x0012\x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0170\x00&C\x00E \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0171\x00&C\x00F \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0172\x00&C\x00A \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0173\x00&C\x00D \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0174\x00&C\x00N \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0175\x00&C\x00O \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0176\x00&C\x00X \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0177\x00&C\x00C \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0178\x00&C\x00V \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0179\x00&C\x00Z \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0180\x00&C\x00&1\x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0181\x00&1\x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0182\x00&2\x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0183\x00&C\x00&2\x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0184\x00&C\x00G \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0185\x00&C\x00R \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0186\x00&C\x00P \x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='\x0194\x00&S\x00&F\x0010\x00\x00', item_type=16, item_id=6, item_sid=19),
                SAPDiagItem(item_value='&0\x00Enter\x00', item_type=16, item_id=6, item_sid=20),
                SAPDiagItem(item_value='&1\x00Page up\x00', item_type=16, item_id=6, item_sid=20),
                SAPDiagItem(item_value='&2\x00Page down\x00', item_type=16, item_id=6, item_sid=20),
                SAPDiagItem(item_value='&3\x00First page\x00', item_type=16, item_id=6, item_sid=20),
                SAPDiagItem(item_value='&4\x00Prev. page\x00', item_type=16, item_id=6, item_sid=20),
                SAPDiagItem(item_value='&5\x00Next page\x00', item_type=16, item_id=6, item_sid=20),
                SAPDiagItem(item_value='&6\x00Last page\x00', item_type=16, item_id=6, item_sid=20),
                SAPDiagItem(item_value='&A\x00Alt\x00', item_type=16, item_id=6, item_sid=20),
                SAPDiagItem(item_value='&B\x00Backsp.\x00', item_type=16, item_id=6, item_sid=20),
                SAPDiagItem(item_value='&C\x00Ctrl\x00', item_type=16, item_id=6, item_sid=20),
                SAPDiagItem(item_value='&D\x00Del\x00', item_type=16, item_id=6, item_sid=20),
                SAPDiagItem(item_value='&E\x00Esc\x00', item_type=16, item_id=6, item_sid=20),
                SAPDiagItem(item_value='&F\x00F\x00', item_type=16, item_id=6, item_sid=20),
                SAPDiagItem(item_value='&I\x00Ins.\x00', item_type=16, item_id=6, item_sid=20),
                SAPDiagItem(item_value='&L\x00Arrow <--\x00', item_type=16, item_id=6, item_sid=20),
                SAPDiagItem(item_value='&S\x00Shift\x00', item_type=16, item_id=6, item_sid=20),
                SAPDiagItem(item_value='\x00\xc8', item_type=16, item_id=6, item_sid=6),
                SAPDiagItem(item_value='S000                                ', item_type=16, item_id=6, item_sid=7),
                SAPDiagItem(item_value=SAPDiagSES(screen_flag=33, dim_col=84, dim_row=22), item_type=1),
                SAPDiagItem(item_value=SAPDiagAreaSize(area_height=22, area_width=84, window_width=84, window_height=22), item_type=16, item_id=12, item_sid=7),
                SAPDiagItem(item_value=',', item_type=16, item_id=4, item_sid=26),
                SAPDiagItem(item_value='E', item_type=16, item_id=4, item_sid=27),
                SAPDiagItem(item_value='            ', item_type=16, item_id=4, item_sid=28),
                SAPDiagItem(item_value=self.client_no, item_type=16, item_id=6, item_sid=12),
                SAPDiagItem(item_value='SAP R/3 (1) %s     ' % self.sid, item_type=16, item_id=12, item_sid=10),
                SAPDiagItem(item_value='SAPMSYST                                ', item_type=16, item_id=6, item_sid=15),
                SAPDiagItem(item_value='0020                ', item_type=16, item_id=6, item_sid=16),
                SAPDiagItem(item_value='SAPMSYST                                ', item_type=16, item_id=6, item_sid=13),
                SAPDiagItem(item_value='0020', item_type=16, item_id=6, item_sid=14),
                SAPDiagItem(item_value=SAPDiagMenuEntries(entries=[SAPDiagMenuEntry(accelerator='U', text='User', flag_TERM_VKEY=1L, flag_TERM_MEN=1L, position_1=1, flag_TERM_SEL=1L, return_code_1=1, info='', length=28),
                                                                   SAPDiagMenuEntry(accelerator='y', text='System', flag_TERM_VKEY=1L, flag_TERM_MEN=1L, position_1=2, flag_TERM_SEL=1L, return_code_1=2, info='', length=30),
                                                                   SAPDiagMenuEntry(accelerator='H', text='Help', flag_TERM_VKEY=1L, flag_TERM_MEN=1L, position_1=3, flag_TERM_SEL=1L, return_code_1=3, info='', length=28)]), item_type=18, item_id=11, item_sid=1),
                SAPDiagItem(item_value=SAPDiagMenuEntries(entries=[SAPDiagMenuEntry(accelerator='L', text='Log on', virtual_key=100, position_2=1, position_1=1, flag_TERM_SEL=1L, return_code_2=1, return_code_1=1, info='', length=30),
                                                                   SAPDiagMenuEntry(accelerator='N', text='New password', flag_TERM_VKEY=1L, virtual_key=5, position_2=2, position_1=1, flag_TERM_SEL=1L, return_code_2=2, return_code_1=1, info='', length=36),
                                                                   SAPDiagMenuEntry(accelerator='O', text='Log off', flag_TERM_VKEY=1L, virtual_key=15, position_2=3, position_1=1, flag_TERM_SEL=1L, return_code_2=3, return_code_1=1, info='', length=31),
                                                                   SAPDiagMenuEntry(accelerator='E', text='Create Session', virtual_key=100, position_2=1, position_1=2, return_code_2=1, return_code_1=2, info='', length=38),
                                                                   SAPDiagMenuEntry(accelerator='D', text='End Session', virtual_key=100, position_2=2, position_1=2, return_code_2=2, return_code_1=2, info='', length=35),
                                                                   SAPDiagMenuEntry(accelerator='U', text='User Profile', flag_TERM_MEN=1L, virtual_key=100, position_2=3, position_1=2, flag_TERM_SEL=1L, return_code_2=3, return_code_1=2, info='', length=36),
                                                                   SAPDiagMenuEntry(accelerator='I', text='Services', flag_TERM_MEN=1L, virtual_key=100, position_2=4, position_1=2, flag_TERM_SEL=1L, return_code_2=4, return_code_1=2, info='', length=32),
                                                                   SAPDiagMenuEntry(accelerator='M', text='Utilities', flag_TERM_MEN=1L, virtual_key=100, position_2=5, position_1=2, flag_TERM_SEL=1L, return_code_2=5, return_code_1=2, info='', length=33),
                                                                   SAPDiagMenuEntry(accelerator='T', text='List', flag_TERM_MEN=1L, virtual_key=100, position_2=6, position_1=2, flag_TERM_SEL=1L, return_code_2=6, return_code_1=2, info='', length=28),
                                                                   SAPDiagMenuEntry(accelerator='R', text='Services for Object', virtual_key=100, position_2=7, position_1=2, return_code_2=7, return_code_1=2, info='', length=43),
                                                                   SAPDiagMenuEntry(accelerator='O', text='My Objects', flag_TERM_MEN=1L, virtual_key=100, position_2=8, position_1=2, flag_TERM_SEL=1L, return_code_2=8, return_code_1=2, info='', length=34),
                                                                   SAPDiagMenuEntry(accelerator='P', text='Own Spool Requests', virtual_key=100, position_2=9, position_1=2, return_code_2=9, return_code_1=2, info='', length=42),
                                                                   SAPDiagMenuEntry(accelerator='W', text='Own Jobs', virtual_key=100, position_2=10, position_1=2, return_code_2=10, return_code_1=2, info='', length=32),
                                                                   SAPDiagMenuEntry(accelerator='H', text='Short Message', virtual_key=100, position_2=11, position_1=2, return_code_2=11, return_code_1=2, info='', length=37),
                                                                   SAPDiagMenuEntry(accelerator='S', text='Status...', virtual_key=100, position_2=12, position_1=2, return_code_2=12, return_code_1=2, info='', length=33),
                                                                   SAPDiagMenuEntry(accelerator='F', text='Log off', virtual_key=100, position_2=13, position_1=2, flag_TERM_SEL=1L, return_code_2=13, return_code_1=2, info='', length=31),
                                                                   SAPDiagMenuEntry(accelerator='H', text='Hold Data', virtual_key=100, position_2=3, position_1=2, return_code_2=3, return_code_3=1, return_code_1=2, position_3=1, info='', length=33),
                                                                   SAPDiagMenuEntry(accelerator='S', text='Set Data', virtual_key=100, position_2=3, position_1=2, return_code_2=3, return_code_3=2, return_code_1=2, position_3=2, info='', length=32),
                                                                   SAPDiagMenuEntry(accelerator='L', text='Delete Data', virtual_key=100, position_2=3, position_1=2, return_code_2=3, return_code_3=3, return_code_1=2, position_3=3, info='', length=35),
                                                                   SAPDiagMenuEntry(accelerator='O', text='Own Data', virtual_key=100, position_2=3, position_1=2, return_code_2=3, return_code_3=4, return_code_1=2, position_3=4, info='', length=32),
                                                                   SAPDiagMenuEntry(accelerator='F', text='Expand Favorites', virtual_key=100, position_2=3, position_1=2, return_code_2=3, return_code_3=5, return_code_1=2, position_3=5, info='', length=40),
                                                                   SAPDiagMenuEntry(accelerator='R', text='Reporting', virtual_key=100, position_2=4, position_1=2, return_code_2=4, return_code_3=1, return_code_1=2, position_3=1, info='', length=33),
                                                                   SAPDiagMenuEntry(accelerator='Q', text='QuickViewer', virtual_key=100, position_2=4, position_1=2, return_code_2=4, return_code_3=2, return_code_1=2, position_3=2, info='', length=35),
                                                                   SAPDiagMenuEntry(accelerator='O', text='Output Control', virtual_key=100, position_2=4, position_1=2, return_code_2=4, return_code_3=3, return_code_1=2, position_3=3, info='', length=38),
                                                                   SAPDiagMenuEntry(accelerator='T', text='Table Maintenance', flag_TERM_MEN=1L, virtual_key=100, position_2=4, position_1=2, flag_TERM_SEL=1L, return_code_2=4, return_code_3=4, return_code_1=2, position_3=4, info='', length=41),
                                                                   SAPDiagMenuEntry(accelerator='I', text='Batch Input', flag_TERM_MEN=1L, virtual_key=100, position_2=4, position_1=2, flag_TERM_SEL=1L, return_code_2=4, return_code_3=5, return_code_1=2, position_3=5, info='', length=35),
                                                                   SAPDiagMenuEntry(accelerator='F', text='Fast Entry', flag_TERM_MEN=1L, virtual_key=100, position_2=4, position_1=2, flag_TERM_SEL=1L, return_code_2=4, return_code_3=6, return_code_1=2, position_3=6, info='', length=34),
                                                                   SAPDiagMenuEntry(accelerator='D', text='Direct Input', virtual_key=100, position_2=4, position_1=2, return_code_2=4, return_code_3=7, return_code_1=2, position_3=7, info='', length=36),
                                                                   SAPDiagMenuEntry(accelerator='B', text='Jobs', flag_TERM_MEN=1L, virtual_key=100, position_2=4, position_1=2, flag_TERM_SEL=1L, return_code_2=4, return_code_3=8, return_code_1=2, position_3=8, info='', length=28),
                                                                   SAPDiagMenuEntry(accelerator='U', text='Queue', virtual_key=100, position_2=4, position_1=2, return_code_2=4, return_code_3=9, return_code_1=2, position_3=9, info='', length=29),
                                                                   SAPDiagMenuEntry(accelerator='S', text='SAP Service', virtual_key=100, position_2=4, position_1=2, return_code_2=4, return_code_3=10, return_code_1=2, position_3=10, info='', length=35),
                                                                   SAPDiagMenuEntry(accelerator='E', text='Extended Table Maintenance', virtual_key=100, position_2=4, position_1=2, return_code_2=4, return_code_3=4, position_4=1, return_code_1=2, position_3=4, return_code_4=1, info='', length=50),
                                                                   SAPDiagMenuEntry(accelerator='V', text='View Cluster Maintenance', virtual_key=100, position_2=4, position_1=2, return_code_2=4, return_code_3=4, position_4=2, return_code_1=2, position_3=4, return_code_4=2, info='', length=48),
                                                                   SAPDiagMenuEntry(accelerator='E', text='Sessions', virtual_key=100, position_2=4, position_1=2, return_code_2=4, return_code_3=5, position_4=1, return_code_1=2, position_3=5, return_code_4=1, info='', length=32),
                                                                   SAPDiagMenuEntry(accelerator='L', text='Logs', virtual_key=100, position_2=4, position_1=2, return_code_2=4, return_code_3=5, position_4=2, return_code_1=2, position_3=5, return_code_4=2, info='', length=28),
                                                                   SAPDiagMenuEntry(accelerator='C', text='Recorder', virtual_key=100, position_2=4, position_1=2, return_code_2=4, return_code_3=5, position_4=3, return_code_1=2, position_3=5, return_code_4=3, info='', length=32),
                                                                   SAPDiagMenuEntry(accelerator='', text='', virtual_key=100, flag_TERM_SEP=1L, position_2=4, position_1=2, return_code_2=4, return_code_3=5, position_4=4, return_code_1=2, position_3=5, return_code_4=4, info='', length=23),
                                                                   SAPDiagMenuEntry(accelerator='R', text='Restart Transaction', virtual_key=100, position_2=4, position_1=2, return_code_2=4, return_code_3=5, position_4=5, return_code_1=2, position_3=5, return_code_4=5, info='', length=43),
                                                                   SAPDiagMenuEntry(accelerator='T', text='Delete Transaction', virtual_key=100, position_2=4, position_1=2, return_code_2=4, return_code_3=5, position_4=6, return_code_1=2, position_3=5, return_code_4=6, info='', length=42),
                                                                   SAPDiagMenuEntry(accelerator='N', text='Next Transaction', virtual_key=100, position_2=4, position_1=2, return_code_2=4, return_code_3=5, position_4=7, return_code_1=2, position_3=5, return_code_4=7, info='', length=40),
                                                                   SAPDiagMenuEntry(accelerator='', text='', virtual_key=100, flag_TERM_SEP=1L, position_2=4, position_1=2, return_code_2=4, return_code_3=5, position_4=8, return_code_1=2, position_3=5, return_code_4=8, info='', length=23),
                                                                   SAPDiagMenuEntry(accelerator='S', text='Process in Foreground', virtual_key=100, position_2=4, position_1=2, return_code_2=4, return_code_3=5, position_4=9, return_code_1=2, position_3=5, return_code_4=9, info='', length=45),
                                                                   SAPDiagMenuEntry(accelerator='D', text='Display Errors Only', virtual_key=100, position_2=4, position_1=2, return_code_2=4, return_code_3=5, position_4=10, return_code_1=2, position_3=5, return_code_4=10, info='', length=43),
                                                                   SAPDiagMenuEntry(accelerator='X', text='Expert Mode On', virtual_key=100, position_2=4, position_1=2, return_code_2=4, return_code_3=5, position_4=11, return_code_1=2, position_3=5, return_code_4=11, info='', length=38),
                                                                   SAPDiagMenuEntry(accelerator='O', text='Expert Mode Off', virtual_key=100, position_2=4, position_1=2, return_code_2=4, return_code_3=5, position_4=12, return_code_1=2, position_3=5, return_code_4=12, info='', length=39),
                                                                   SAPDiagMenuEntry(accelerator='', text='', virtual_key=100, flag_TERM_SEP=1L, position_2=4, position_1=2, return_code_2=4, return_code_3=5, position_4=13, return_code_1=2, position_3=5, return_code_4=13, info='', length=23),
                                                                   SAPDiagMenuEntry(accelerator='A', text='Cancel', virtual_key=100, position_2=4, position_1=2, return_code_2=4, return_code_3=5, position_4=14, return_code_1=2, position_3=5, return_code_4=14, info='', length=30),
                                                                   SAPDiagMenuEntry(accelerator='C', text='Recorder', virtual_key=100, position_2=4, position_1=2, return_code_2=4, return_code_3=6, position_4=1, return_code_1=2, position_3=6, return_code_4=1, info='', length=32),
                                                                   SAPDiagMenuEntry(accelerator='', text='', virtual_key=100, flag_TERM_SEP=1L, position_2=4, position_1=2, return_code_2=4, return_code_3=6, position_4=2, return_code_1=2, position_3=6, return_code_4=2, info='', length=23),
                                                                   SAPDiagMenuEntry(accelerator='S', text='Process in Foreground', virtual_key=100, position_2=4, position_1=2, return_code_2=4, return_code_3=6, position_4=3, return_code_1=2, position_3=6, return_code_4=3, info='', length=45),
                                                                   SAPDiagMenuEntry(accelerator='D', text='Display Errors Only', virtual_key=100, position_2=4, position_1=2, return_code_2=4, return_code_3=6, position_4=4, return_code_1=2, position_3=6, return_code_4=4, info='', length=43),
                                                                   SAPDiagMenuEntry(accelerator='', text='', virtual_key=100, flag_TERM_SEP=1L, position_2=4, position_1=2, return_code_2=4, return_code_3=6, position_4=5, return_code_1=2, position_3=6, return_code_4=5, info='', length=23),
                                                                   SAPDiagMenuEntry(accelerator='A', text='Cancel', virtual_key=100, position_2=4, position_1=2, return_code_2=4, return_code_3=6, position_4=6, return_code_1=2, position_3=6, return_code_4=6, info='', length=30),
                                                                   SAPDiagMenuEntry(accelerator='B', text='Define Job', virtual_key=100, position_2=4, position_1=2, return_code_2=4, return_code_3=8, position_4=1, return_code_1=2, position_3=8, return_code_4=1, info='', length=34),
                                                                   SAPDiagMenuEntry(accelerator='J', text='Job Overview', virtual_key=100, position_2=4, position_1=2, return_code_2=4, return_code_3=8, position_4=2, return_code_1=2, position_3=8, return_code_4=2, info='', length=36),
                                                                   SAPDiagMenuEntry(accelerator='D', text='Debug Screen', virtual_key=100, position_2=5, position_1=2, return_code_2=5, return_code_3=1, return_code_1=2, position_3=1, info='', length=36),
                                                                   SAPDiagMenuEntry(accelerator='E', text='Debugging ABAP', virtual_key=100, position_2=5, position_1=2, return_code_2=5, return_code_3=2, return_code_1=2, position_3=2, info='', length=38),
                                                                   SAPDiagMenuEntry(accelerator='B', text='Debug System', virtual_key=100, position_2=5, position_1=2, return_code_2=5, return_code_3=3, return_code_1=2, position_3=3, info='', length=36),
                                                                   SAPDiagMenuEntry(accelerator='S', text='Resource Usage', virtual_key=100, position_2=5, position_1=2, return_code_2=5, return_code_3=4, return_code_1=2, position_3=4, info='', length=38),
                                                                   SAPDiagMenuEntry(accelerator='U', text='Autom. Queue: Synchronous Processing', virtual_key=100, position_2=5, position_1=2, return_code_2=5, return_code_3=5, return_code_1=2, position_3=5, info='', length=60),
                                                                   SAPDiagMenuEntry(accelerator='P', text='Performance Trace', virtual_key=100, position_2=5, position_1=2, return_code_2=5, return_code_3=6, return_code_1=2, position_3=6, info='', length=41),
                                                                   SAPDiagMenuEntry(accelerator='C', text='Context Trace', virtual_key=100, position_2=5, position_1=2, return_code_2=5, return_code_3=7, return_code_1=2, position_3=7, info='', length=37),
                                                                   SAPDiagMenuEntry(accelerator='L', text='Runtime Analysis', flag_TERM_MEN=1L, virtual_key=100, position_2=5, position_1=2, flag_TERM_SEL=1L, return_code_2=5, return_code_3=8, return_code_1=2, position_3=8, info='', length=40),
                                                                   SAPDiagMenuEntry(accelerator='A', text='Display Authorization Check', virtual_key=100, position_2=5, position_1=2, return_code_2=5, return_code_3=9, return_code_1=2, position_3=9, info='', length=51),
                                                                   SAPDiagMenuEntry(accelerator='I', text='Memory Analysis', flag_TERM_MEN=1L, virtual_key=100, position_2=5, position_1=2, flag_TERM_SEL=1L, return_code_2=5, return_code_3=10, return_code_1=2, position_3=10, info='', length=39),
                                                                   SAPDiagMenuEntry(accelerator='X', text='Execute', virtual_key=100, position_2=5, position_1=2, return_code_2=5, return_code_3=8, position_4=1, return_code_1=2, position_3=8, return_code_4=1, info='', length=31),
                                                                   SAPDiagMenuEntry(accelerator='S', text='Switch On', virtual_key=100, position_2=5, position_1=2, return_code_2=5, return_code_3=8, position_4=2, return_code_1=2, position_3=8, return_code_4=2, info='', length=33),
                                                                   SAPDiagMenuEntry(accelerator='W', text='Switch Off', virtual_key=100, position_2=5, position_1=2, return_code_2=5, return_code_3=8, position_4=3, return_code_1=2, position_3=8, return_code_4=3, info='', length=34),
                                                                   SAPDiagMenuEntry(accelerator='S', text='Create Memory Snapshot', virtual_key=100, position_2=5, position_1=2, return_code_2=5, return_code_3=10, position_4=1, return_code_1=2, position_3=10, return_code_4=1, info='', length=46),
                                                                   SAPDiagMenuEntry(accelerator='P', text='Compare Memory Snapshots', virtual_key=100, position_2=5, position_1=2, return_code_2=5, return_code_3=10, position_4=2, return_code_1=2, position_3=10, return_code_4=2, info='', length=48),
                                                                   SAPDiagMenuEntry(accelerator='P', text='Print', virtual_key=100, position_2=6, position_1=2, return_code_2=6, return_code_3=1, return_code_1=2, position_3=1, info='', length=29),
                                                                   SAPDiagMenuEntry(accelerator='F', text='Find...', virtual_key=100, position_2=6, position_1=2, return_code_2=6, return_code_3=2, return_code_1=2, position_3=2, info='', length=31),
                                                                   SAPDiagMenuEntry(accelerator='A', text='Save', flag_TERM_MEN=1L, virtual_key=100, position_2=6, position_1=2, flag_TERM_SEL=1L, return_code_2=6, return_code_3=3, return_code_1=2, position_3=3, info='', length=28),
                                                                   SAPDiagMenuEntry(accelerator='E', text='Send', virtual_key=100, position_2=6, position_1=2, return_code_2=6, return_code_3=4, return_code_1=2, position_3=4, info='', length=28),
                                                                   SAPDiagMenuEntry(accelerator='L', text='List Header', virtual_key=100, position_2=6, position_1=2, return_code_2=6, return_code_3=5, return_code_1=2, position_3=5, info='', length=35),
                                                                   SAPDiagMenuEntry(accelerator='O', text='Office Folders', virtual_key=100, position_2=6, position_1=2, return_code_2=6, return_code_3=3, position_4=1, return_code_1=2, position_3=3, return_code_4=1, info='', length=38),
                                                                   SAPDiagMenuEntry(accelerator='R', text='Report Tree', virtual_key=100, position_2=6, position_1=2, return_code_2=6, return_code_3=3, position_4=2, return_code_1=2, position_3=3, return_code_4=2, info='', length=35),
                                                                   SAPDiagMenuEntry(accelerator='I', text='Local File', virtual_key=100, position_2=6, position_1=2, return_code_2=6, return_code_3=3, position_4=3, return_code_1=2, position_3=3, return_code_4=3, info='', length=34),
                                                                   SAPDiagMenuEntry(accelerator='O', text='Object History', virtual_key=100, position_2=8, position_1=2, return_code_2=8, return_code_3=1, return_code_1=2, position_3=1, info='', length=38),
                                                                   SAPDiagMenuEntry(accelerator='B', text='Edit Objects', virtual_key=100, position_2=8, position_1=2, return_code_2=8, return_code_3=2, return_code_1=2, position_3=2, info='', length=36),
                                                                   SAPDiagMenuEntry(accelerator='E', text='Application Help', virtual_key=100, position_2=1, position_1=3, return_code_2=1, return_code_1=3, info='', length=40),
                                                                   SAPDiagMenuEntry(accelerator='S', text='SAP Library', virtual_key=100, position_2=2, position_1=3, return_code_2=2, return_code_1=3, info='', length=35),
                                                                   SAPDiagMenuEntry(accelerator='G', text='Glossary', virtual_key=100, position_2=3, position_1=3, return_code_2=3, return_code_1=3, info='', length=32),
                                                                   SAPDiagMenuEntry(accelerator='', text='', virtual_key=100, flag_TERM_SEP=1L, position_2=4, position_1=3, return_code_2=4, return_code_1=3, info='', length=23),
                                                                   SAPDiagMenuEntry(accelerator='R', text='Release Notes', virtual_key=100, position_2=5, position_1=3, return_code_2=5, return_code_1=3, info='', length=37),
                                                                   SAPDiagMenuEntry(accelerator='', text='', virtual_key=100, flag_TERM_SEP=1L, position_2=6, position_1=3, return_code_2=6, return_code_1=3, info='', length=23),
                                                                   SAPDiagMenuEntry(accelerator='A', text='SAP Service Marketplace', virtual_key=100, position_2=7, position_1=3, return_code_2=7, return_code_1=3, info='', length=47),
                                                                   SAPDiagMenuEntry(accelerator='', text='', virtual_key=100, flag_TERM_SEP=1L, position_2=8, position_1=3, return_code_2=8, return_code_1=3, info='', length=23),
                                                                   SAPDiagMenuEntry(accelerator='C', text='Create Support Message', virtual_key=100, position_2=9, position_1=3, return_code_2=9, return_code_1=3, info='', length=46),
                                                                   SAPDiagMenuEntry(accelerator='', text='', virtual_key=100, flag_TERM_SEP=1L, position_2=10, position_1=3, return_code_2=10, return_code_1=3, info='', length=23),
                                                                   SAPDiagMenuEntry(accelerator='N', text='Settings...', virtual_key=100, position_2=11, position_1=3, return_code_2=11, return_code_1=3, info='', length=35)]), item_type=18, item_id=11, item_sid=2),
                SAPDiagItem(item_value=SAPDiagMenuEntries(entries=[SAPDiagMenuEntry(accelerator='', text='New password', virtual_key=5, position_1=0, flag_TERM_SEL=1L, return_code_1=5, info='New password', length=47)]), item_type=18, item_id=11, item_sid=3),
                SAPDiagItem(item_value=SAPDiagMenuEntries(entries=[SAPDiagMenuEntry(accelerator='', text='New password', virtual_key=5, position_1=1, flag_TERM_SEL=1L, info='', length=35),
                                                                   SAPDiagMenuEntry(accelerator='', text='Log off', virtual_key=15, position_1=2, flag_TERM_SEL=1L, return_code_1=1, info='', length=30)]), item_type=18, item_id=11, item_sid=4),
                SAPDiagItem(item_value='SAP', item_type=16, item_id=12, item_sid=9),
                SAPDiagItem(item_value='\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x11[\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', item_type=16, item_id=5, item_sid=1),
                SAPDiagItem(item_value='\x00\x00\x00\x11\x00\x00\x00[\x00\x00\x00\x11\x00\x00\x00[\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x16\x00\x00\x00T\x01', item_type=16, item_id=12, item_sid=6),
                SAPDiagItem(item_value='\x00\x00\x00\x00\x00\x00\x00\x00\x00', item_type=16, item_id=10, item_sid=1),
                SAPDiagItem(item_value=SAPDiagDyntAtom(items=[SAPDiagDyntAtomItem(field2_maxnrchars=18, attr_DIAG_BSD_PROPFONT=1L, dlg_flag_2=2, atom_length=37, field2_mlen=18, etype=132, field2_dlen=18, attr_DIAG_BSD_PROTECTED=1L, col=1, block=1, field2_text='Client            '),
                                                              SAPDiagDyntAtomItem(attr_DIAG_BSD_PROPFONT=1L, dlg_flag_2=2, atom_length=24, etype=114, name_text='RSYST-MANDT', attr_DIAG_BSD_PROTECTED=1L, col=1, block=1),
                                                              SAPDiagDyntAtomItem(field2_maxnrchars=3, atom_length=22, field2_mlen=3, etype=130, attr_DIAG_BSD_YES3D=1L, field2_dlen=3, col=20, block=1, field2_text=self.client_no),
                                                              SAPDiagDyntAtomItem(atom_length=24, etype=114, name_text='RSYST-MANDT', attr_DIAG_BSD_YES3D=1L, col=20, block=1),
                                                              SAPDiagDyntAtomItem(atom_length=79, etype=120, attr_DIAG_BSD_YES3D=1L, xmlprop_text='<Propertybag><DefaultTooltip>Client</DefaultTooltip></Propertybag>', col=20, block=1),
                                                              SAPDiagDyntAtomItem(field2_maxnrchars=18, attr_DIAG_BSD_PROPFONT=1L, dlg_flag_2=3, atom_length=37, field2_mlen=18, etype=132, row=2, field2_dlen=18, attr_DIAG_BSD_PROTECTED=1L, col=1, block=1, field2_text='User              '),
                                                              SAPDiagDyntAtomItem(attr_DIAG_BSD_PROPFONT=1L, dlg_flag_2=3, atom_length=24, etype=114, name_text='RSYST-BNAME', row=2, attr_DIAG_BSD_PROTECTED=1L, col=1, block=1),
                                                              SAPDiagDyntAtomItem(field2_maxnrchars=12, dlg_flag_2=1, atom_length=31, field2_mlen=12, etype=130, row=2, attr_DIAG_BSD_YES3D=1L, field2_dlen=12, col=20, block=1, field2_text='?           '),
                                                              SAPDiagDyntAtomItem(dlg_flag_2=1, atom_length=24, etype=114, name_text='RSYST-BNAME', row=2, attr_DIAG_BSD_YES3D=1L, col=20, block=1),
                                                              SAPDiagDyntAtomItem(dlg_flag_2=1, atom_length=82, etype=120, row=2, attr_DIAG_BSD_YES3D=1L, xmlprop_text='<Propertybag><DefaultTooltip>User name</DefaultTooltip></Propertybag>', col=20, block=1),
                                                              SAPDiagDyntAtomItem(field2_maxnrchars=52, attr_DIAG_BSD_PROPFONT=1L, dlg_flag_2=3, dlg_flag_1=4, atom_length=71, field2_mlen=18, etype=132, row=3, field2_dlen=52, attr_DIAG_BSD_PROTECTED=1L, col=1, block=1, field2_text='@\\QUp to 40 Chars (Case-Sens.)@Password             '),
                                                              SAPDiagDyntAtomItem(attr_DIAG_BSD_PROPFONT=1L, dlg_flag_2=3, dlg_flag_1=4, atom_length=24, etype=114, name_text='RSYST-BCODE', row=3, attr_DIAG_BSD_PROTECTED=1L, col=1, block=1),
                                                              SAPDiagDyntAtomItem(field2_maxnrchars=40, attr_DIAG_BSD_INVISIBLE=1L, dlg_flag_2=1, dlg_flag_1=4, atom_length=59, field2_mlen=12, etype=130, row=3, attr_DIAG_BSD_YES3D=1L, field2_dlen=40, col=20, block=1, field2_text='?                                       '),
                                                              SAPDiagDyntAtomItem(attr_DIAG_BSD_INVISIBLE=1L, dlg_flag_2=1, dlg_flag_1=4, atom_length=24, etype=114, name_text='RSYST-BCODE', row=3, attr_DIAG_BSD_YES3D=1L, col=20, block=1),
                                                              SAPDiagDyntAtomItem(attr_DIAG_BSD_INVISIBLE=1L, dlg_flag_2=1, dlg_flag_1=4, atom_length=86, etype=120, row=3, attr_DIAG_BSD_YES3D=1L, xmlprop_text='<Propertybag><DefaultTooltip>User password</DefaultTooltip></Propertybag>', col=20, block=1),
                                                              SAPDiagDyntAtomItem(field2_maxnrchars=18, attr_DIAG_BSD_PROPFONT=1L, dlg_flag_2=2, atom_length=37, field2_mlen=18, etype=132, row=5, field2_dlen=18, attr_DIAG_BSD_PROTECTED=1L, col=1, block=1, field2_text='Language          '),
                                                              SAPDiagDyntAtomItem(attr_DIAG_BSD_PROPFONT=1L, dlg_flag_2=2, atom_length=24, etype=114, name_text='RSYST-LANGU', row=5, attr_DIAG_BSD_PROTECTED=1L, col=1, block=1),
                                                              SAPDiagDyntAtomItem(field2_maxnrchars=2, atom_length=21, field2_mlen=2, etype=130, row=5, attr_DIAG_BSD_YES3D=1L, field2_dlen=2, col=20, block=1, field2_text='  '),
                                                              SAPDiagDyntAtomItem(atom_length=24, etype=114, name_text='RSYST-LANGU', row=5, attr_DIAG_BSD_YES3D=1L, col=20, block=1),
                                                              SAPDiagDyntAtomItem(atom_length=81, etype=120, row=5, attr_DIAG_BSD_YES3D=1L, xmlprop_text='<Propertybag><DefaultTooltip>Language</DefaultTooltip></Propertybag>', col=20, block=1)]), item_type=18, item_id=9, item_sid=2),
                SAPDiagItem(item_value='\x00\x00\x00\x00\x00\x00\x00\x00\x00', item_type=16, item_id=10, item_sid=1),
                SAPDiagItem(item_value='\x02\x00\x06\x00\x01\x00\x1f\x00\x0b', item_type=16, item_id=10, item_sid=5),
                SAPDiagItem(item_value='TC_IUSRACL\x00SAPMSYST\x000020\x00', item_type=16, item_id=10, item_sid=6),
                SAPDiagItem(item_value='\x01\x00\x02\x00\x14\x00\x00\x00\x00\x00', item_type=16, item_id=9, item_sid=11),
                SAPDiagItem(item_value=self.make_passport(), item_type=18, item_id=4, item_sid=24),
                SAPDiagItem(item_type=12)
                ]

        return [
            SAPDiagItem(item_value=support_data_sapnw_702, item_type=16, item_id=6, item_sid=17),
            SAPDiagItem(item_value='\x01\xa3\x8a\x17\xe1\\F\xf1\xf6\xb4<\x00\x0c)}.\x11\x01', item_type=16, item_id=6, item_sid=31),

        ]

    def make_error_screen(self, message):
        return [SAPDiagItem(item_value=support_data_sapnw_702, item_type=16, item_id=6, item_sid=17),
                SAPDiagItem(item_value=self.context_id, item_type=16, item_id=6, item_sid=33),
                SAPDiagItem(item_value='\x01\x80\x8d\x17\xe1\xe8\xdb\xf1\xd2\xb4<\x00\x0c)}.\x11\x01', item_type=16, item_id=6, item_sid=31),
                SAPDiagItem(item_value=self.sid, item_type=16, item_id=6, item_sid=2),
                SAPDiagItem(item_value=self.client_no, item_type=16, item_id=6, item_sid=12),
                SAPDiagItem(item_value=self.hostname, item_type=16, item_id=6, item_sid=33),
                SAPDiagItem(item_value='TRADESHOW\x00', item_type=16, item_id=6, item_sid=37),
                SAPDiagItem(item_value=self.make_kernel_version(), item_type=16, item_id=6, item_sid=41),
                SAPDiagItem(item_value='SAP R/3 (1) %s     ' % self.sid, item_type=16, item_id=12, item_sid=10),
                SAPDiagItem(item_value='SAPMSYST                                ', item_type=16, item_id=6, item_sid=15),
                SAPDiagItem(item_value='0020                ', item_type=16, item_id=6, item_sid=16),
                SAPDiagItem(item_value='SAPMSYST                                ', item_type=16, item_id=6, item_sid=13),
                SAPDiagItem(item_value='0020', item_type=16, item_id=6, item_sid=14),
                SAPDiagItem(item_value=self.session_title, item_type=16, item_id=12, item_sid=9),
                SAPDiagItem(item_value=message, item_type=16, item_id=6, item_sid=11),
                ]

    def make_passport(self):
        return "*TH*\x03\x00\xe6\x00\x00%(sid)s/%(hostname)s_%(sid)s_00" \
               "           \x00\x01                                                                        \x00" \
               "\x01%(sid)s/%(hostname)s_%(sid)s_00           %(context_id)s\x00" \
               "\x01\x08\x00'\xf6W\xe5\x1e\xe4\xb6\x82\xf8\x15\x98\x9c>:\x00" \
               "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe2*TH*" % {"sid": self.sid,
                                                                                                                     "hostname": self.hostname,
                                                                                                                     "context_id": self.context_id}

    def make_context_id(self):
        return ''.join(SystemRandom().choice(string.hexdigits) for _ in range(32)).upper()

    def make_kernel_version(self):
        return "%s\x00%s\x00%s\x00" % (self.database_version,
                                       self.kernel_version,
                                       self.kernel_patch_level)

    def logoff(self):
        self.logger.debug("Logging off the client %s" % str(self.client_address))
        try:
            response = SAPDiag(com_flag_TERM_EOP=1, com_flag_TERM_EOC=1, compress=0)
            self.request.send(response)
            self.session.add_event("Loggoff client", response=str(response))
            self.request.close()
        except error:
            pass
        del(self.server.clients[self.client_address])


class SAPDispatcherServerThreaded(Loggeable, SAPNIServerThreaded):

    clients_cls = SAPDispatcherClient
    clients_count = 0

    def __init__(self, server_address, RequestHandlerClass,
                 bind_and_activate=False, socket_cls=None, keep_alive=True,
                 base_cls=SAPDiag):
        """Initialization of the SAP Dispatcher threaded server"""
        SAPNIServerThreaded.__init__(self, server_address, RequestHandlerClass,
                                     bind_and_activate, socket_cls, keep_alive,
                                     base_cls=base_cls)


class SAPDispatcherService(BaseTCPService):

    server_cls = SAPDispatcherServerThreaded
    handler_cls = SAPDispatcherServerHandler
