# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, ChoicesSetting
import typing as t

PCD_TO_PICC_OUTPUT_TYPE = "pcd_to_picc"
PICC_TO_PCD_OUTPUT_TYPE = "picc_to_pcd"

DIRECTION_SETTING_PCD_TO_PICC = "PCD to PICC"
DIRECTION_SETTING_PICC_TO_PCD = "PICC to PCD"

PROTOCOL_SETTING_NONE = "None"
PROTOCOL_SETTING_DESFIRE = "DESFire"

REQA = 0x26
WUPA = 0x52
RATS = 0xE0
SEL_CASCADE_LEVEL_1 = 0x93
SEL_CASCADE_LEVEL_2 = 0x95
SEL_CASCADE_LEVEL_3 = 0x97
CT = 0x88  # Cascade Tag

PCB_BYTE_SIZE = 1
CRC_BYTE_SIZE = 2
CID_BYTE_SIZE = 1
NAD_BYTE_SIZE = 1

PCB_CID_MASK = 0b00001000
PCB_CID_FOLLOWING = 0b00001000

PCB_NAD_MASK = 0b00000100
PCB_NAD_FOLLOWING = 0b00000100

PCB_BLOCK_NBR_MASK = 0b00000001
PCB_BLOCK_NBR = 0b00000001

PCB_I_BLOCK_MASK = 0b11100010
PCB_I_BLOCK = 0b00000010

PCB_I_CHANING_MASK = 0b00010000
PCB_I_CHANING = 0b00010000

PCB_R_BLOCK_MASK = 0b11100110
PCB_R_BLOCK = 0b10100010

PCB_R_ACK_NAK_MASK = 0b00010000
PCB_R_ACK = 0b00000000
PCB_R_NAK = 0b00010000

PCB_S_BLOCK_MASK = 0b11000101
PCB_S_BLOCK = 0b11000000

PCB_S_DESELECT_MASK = 0b00110010
PCB_S_DESELECT = 0b00000010

PCB_S_WTX_MASK = 0b00110010
PCB_S_WTX = 0b00110010

PCB_S_PARAMETERS_MASK = 0b00110010
PCB_S_PARAMETERS = 0b00110000


ISO_CMDS = {
    0xA4: "ISOSelectFile",
    0xB0: "ISOReadBinary",
    0xD6: "ISOUpdateBinary",
    0xB2: "ISOReadRecord",
    0xE2: "ISOAppendRecord",
    0x84: "ISOGetChallenge",
    0x82: "ISOExternalAuthenticate",
    0x88: "ISOInternalAuthenticate",
}

DESFIRE_CMDS = {
    0x0A: "Authenticate",
    0x1A: "AuthenticateISO",
    0xAA: "AuthenticateAES",
    0x71: "AuthenticateEV2First",
    0x77: "AuthenticateEV2NonFirst",
    0x6E: "FreeMem",
    0xFC: "Format",
    0x5C: "SetConfiguration",
    0x60: "GetVersion",
    0x51: "GetCardUID",
    0xC4: "ChangeKey",
    0xC6: "ChangeKeyEV2",
    0x56: "InitializeKeySet",
    0x57: "FinalizeKeySet",
    0x55: "RollKeySet",
    0x45: "GetKeySettings",
    0x54: "ChangeKeySettings",
    0x64: "GetKeyVersion",
    0xCA: "CreateApplication",
    0xDA: "DeleteApplication",
    0xC9: "CreateDelegatedApplication",
    0x5A: "SelectApplication",
    0x6A: "GetApplicationIDs",
    0x6D: "GetDFNames",
    0x69: "GetDelegatedInfo",
    0xCD: "CreateStdDataFile",
    0xCB: "CreateBackupDataFile",
    0xCC: "CreateValueFile",
    0xC1: "CreateLinearRecordFile",
    0xC0: "CreateCyclicRecordFile",
    0xCE: "CreateTransactionMACFile",
    0xDF: "DeleteFile",
    0x6F: "GetFileIDs",
    0x61: "GetISOFileIDs",
    0xF5: "GetFileSettings",
    0xF6: "GetFileCounters",
    0x5F: "ChangeFileSettings",
    0xBD: "ReadData",
    0xAD: "ReadData",
    0x3D: "WriteData",
    0x8D: "WriteData",
    0x6C: "GetValue",
    0x0C: "Credit",
    0xDC: "Debit",
    0x1C: "LimitedCredit",
    0xBB: "ReadRecords",
    0xAB: "ReadRecords",
    0x3B: "WriteRecord",
    0x8B: "WriteRecord",
    0xDB: "UpdateRecord",
    0xBA: "UpdateRecord",
    0xEB: "ClearRecordFile",
    0xC7: "CommitTransaction",
    0xA7: "AbortTransaction",
    0xC8: "CommitReaderID",
    0xF0: "PreparePC",
    0xF2: "ProximityCheck",
    0xFD: "VerifyPC",
    0x3C: "Read_Sig",
    0xAF: "AdditionalFrame",
}


def calc_bcc(data: bytes) -> int:
    bcc = 0x00
    for b in data:
        bcc = bcc ^ b
    return bcc


def calc_iso14443a_crc(data: bytes) -> bytes:
    crc = 0x6363
    for ch in data:
        ch = ch ^ (crc & 0xFF)
        ch = ch ^ ((ch << 4) & 0xFF)
        crc = (crc >> 8) ^ ((ch << 8) & 0xFFFF) ^ ((ch << 3) & 0xFFFF) ^ (ch >> 4)
    return int.to_bytes(crc, 2, "little")


# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    direction_setting = ChoicesSetting([DIRECTION_SETTING_PCD_TO_PICC, DIRECTION_SETTING_PICC_TO_PCD], label="Data Direction")
    protocol = ChoicesSetting([PROTOCOL_SETTING_NONE, PROTOCOL_SETTING_DESFIRE], label="Protocol")

    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        PCD_TO_PICC_OUTPUT_TYPE: {"format": "{{data.value}}"},
        PICC_TO_PCD_OUTPUT_TYPE: {"format": "{{data.value}}"},
    }

    def __init__(self):
        """
        Initialize HLA.

        Settings can be accessed using the same name used above.
        """

    def decode(self, frame: AnalyzerFrame):
        """
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.

        The type and data values in `frame` will depend on the input analyzer.
        """
        status = frame.data["status"]
        raw_frame = frame.data["value"]
        valid_bits_of_last_byte = frame.data["valid_bits_of_last_byte"]

        if not status == "OK":
            return None
        if not isinstance(raw_frame, bytes):
            return None
        if not isinstance(valid_bits_of_last_byte, int):
            return None

        if self.direction_setting == DIRECTION_SETTING_PCD_TO_PICC:
            value = self.decode_pcd_to_picc(raw_frame, valid_bits_of_last_byte)
            return AnalyzerFrame(PCD_TO_PICC_OUTPUT_TYPE, frame.start_time, frame.end_time, {"value": value})
        elif self.direction_setting == DIRECTION_SETTING_PICC_TO_PCD:
            value = self.decode_picc_to_pcd(raw_frame, valid_bits_of_last_byte)
            return AnalyzerFrame(PICC_TO_PCD_OUTPUT_TYPE, frame.start_time, frame.end_time, {"value": value})
        else:
            return None

    def decode_iso14443a_3_pcd_to_picc(self, raw_frame: bytes, valid_bits_of_last_byte: int) -> t.Optional[str]:
        if valid_bits_of_last_byte == 7:
            if len(raw_frame) == 1:
                if raw_frame[0] == REQA:
                    return "REQA"
                if raw_frame[0] == WUPA:
                    return "WUPA"

        if valid_bits_of_last_byte != 8:
            return None
        if len(raw_frame) < 1:
            return None

        if raw_frame[0] == SEL_CASCADE_LEVEL_1:
            return "SEL (Cascade Level 1)"
        if raw_frame[0] == SEL_CASCADE_LEVEL_2:
            return "SEL (Cascade Level 2)"
        if raw_frame[0] == SEL_CASCADE_LEVEL_3:
            return "SEL (Cascade Level 3)"
        if raw_frame[0] == RATS:
            return "RATS"

    def decode_iso14443a_3_picc_to_pcd(self, raw_frame: bytes, valid_bits_of_last_byte: int) -> t.Optional[str]:
        # An ANTICOLLISION command cannot be detected with an specific byte. So we guess that
        # when the length and the BCC are correct it must be an ANTICOLLISION command
        if len(raw_frame) == 5:
            bcc = calc_bcc(raw_frame[0:4])
            if raw_frame[4] == bcc:
                return "UID"
        return None

    def decode_iso14443a_4(self, raw_frame: bytes, valid_bits_of_last_byte: int, direction: str) -> t.Optional[str]:
        # min. 1 byte PCB + 2 byte crc
        if len(raw_frame) < (PCB_BYTE_SIZE + CRC_BYTE_SIZE):
            return None

        expected_crc = calc_iso14443a_crc(raw_frame[:-CRC_BYTE_SIZE])
        crc_error = expected_crc != raw_frame[-CRC_BYTE_SIZE:]

        frame_info = None

        inf_pos = 1
        cid = None
        cid_str = ""
        nad = None
        nad_str = ""

        if raw_frame[0] & PCB_CID_MASK == PCB_CID_FOLLOWING:
            cid = raw_frame[inf_pos]
            cid_str = f", CID={cid}"
            inf_pos += 1

        if raw_frame[0] & PCB_NAD_MASK == PCB_NAD_FOLLOWING:
            nad = raw_frame[inf_pos]
            nad_str = f", NAD={nad}"
            inf_pos += 1

        inf = raw_frame[inf_pos:-CRC_BYTE_SIZE]

        if raw_frame[0] & PCB_BLOCK_NBR_MASK == PCB_BLOCK_NBR:
            block_nbr = 0
            block_nbr_str = "₀"
        else:
            block_nbr = 1
            block_nbr_str = "₁"

        if raw_frame[0] & PCB_I_BLOCK_MASK == PCB_I_BLOCK:
            if raw_frame[0] & PCB_I_CHANING_MASK == PCB_I_CHANING:
                chaning = True
                chaning_str = "1"
            else:
                chaning = False
                chaning_str = "0"
            data = inf.hex(" ").upper()
            if self.protocol == PROTOCOL_SETTING_DESFIRE:
                if direction == PCD_TO_PICC_OUTPUT_TYPE:
                    cmd_str = self.decode_desfire_picc_to_pcd(inf)
                    data = f"[{cmd_str}] {data}"
            frame_info = f"I({chaning_str}{cid_str}{nad_str}){block_nbr_str}: {data}"
        if raw_frame[0] & PCB_R_BLOCK_MASK == PCB_R_BLOCK:
            if raw_frame[0] & PCB_R_ACK_NAK_MASK == PCB_R_ACK:
                frame_info = f"R(ACK{cid_str}){block_nbr_str}"
            if raw_frame[0] & PCB_R_ACK_NAK_MASK == PCB_R_NAK:
                frame_info = f"R(NAK{cid_str}){block_nbr_str}"
        if raw_frame[0] & PCB_S_BLOCK_MASK == PCB_S_BLOCK:
            if raw_frame[0] & PCB_S_DESELECT_MASK == PCB_S_DESELECT:
                frame_info = f"S(DESELECT{cid_str})"
            if raw_frame[0] & PCB_S_WTX_MASK == PCB_S_WTX:
                frame_info = f"S(WTX{cid_str}): {inf.hex(' ')}"
            if raw_frame[0] & PCB_S_PARAMETERS_MASK == PCB_S_PARAMETERS:
                frame_info = f"S(PARAMETERS{cid_str}): {inf.hex(' ').upper()}"

        if crc_error is True:
            if frame_info is None:
                return "CRC-ERROR"
            else:
                # show the infos even if an crc error occured
                return f"CRC-ERROR ({frame_info}), {expected_crc.hex(' ')=}"

        return frame_info

    def decode_desfire_picc_to_pcd(self, cmd_apdu: bytes) -> str:
        # see NXP AN12752
        if len(cmd_apdu) < 1:
            return "UNKNOWN"

        if cmd_apdu[0] == 0x00:
            if len(cmd_apdu) < 2:
                return "UNKNOWN"

            return ISO_CMDS.get(cmd_apdu[1], "UNKNOWN")
        else:
            return DESFIRE_CMDS.get(cmd_apdu[0], "UNKNOWN")

    def decode_pcd_to_picc(self, raw_frame: bytes, valid_bits_of_last_byte: int) -> str:
        decoded_frame = self.decode_iso14443a_3_pcd_to_picc(raw_frame, valid_bits_of_last_byte)
        if decoded_frame is not None:
            return decoded_frame

        decoded_frame = self.decode_iso14443a_4(raw_frame, valid_bits_of_last_byte, PCD_TO_PICC_OUTPUT_TYPE)
        if decoded_frame is not None:
            return decoded_frame

        return "???"

    def decode_picc_to_pcd(self, raw_frame: bytes, valid_bits_of_last_byte: int) -> str:
        decoded_frame = self.decode_iso14443a_3_picc_to_pcd(raw_frame, valid_bits_of_last_byte)
        if decoded_frame is not None:
            return decoded_frame

        decoded_frame = self.decode_iso14443a_4(raw_frame, valid_bits_of_last_byte, PICC_TO_PCD_OUTPUT_TYPE)
        if decoded_frame is not None:
            return decoded_frame

        return "???"
