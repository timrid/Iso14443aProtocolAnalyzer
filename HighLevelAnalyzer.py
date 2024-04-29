# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame


PCD_TO_PICC_INPUT_TYPE = "pcd_to_picc_raw"
PCD_TO_PICC_OUTPUT_TYPE = "pcd_to_picc"

REQA = 0x26
WUPA = 0x52
RATS = 0xE0

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


def calc_iso14443a_crc(data: bytes) -> bytes:
    crc = 0x6363
    for ch in data:
        ch = ch ^ (crc & 0xFF)
        ch = ch ^ ((ch << 4) & 0xFF)
        crc = (crc >> 8) ^ ((ch << 8) & 0xFFFF) ^ ((ch << 3) & 0xFFFF) ^ (ch >> 4)
    return int.to_bytes(crc, 2, "little")


# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {"pcd_to_picc": {"format": "{{data.value}}"}}

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
        raw_frame = frame.data["value"]
        valid_bits_of_last_byte = frame.data["valid_bits_of_last_byte"]

        if not isinstance(raw_frame, bytes):
            return None
        if not isinstance(valid_bits_of_last_byte, int):
            return None

        if frame.type == PCD_TO_PICC_INPUT_TYPE:
            value = self.decode_pcd_to_picc(raw_frame, valid_bits_of_last_byte)
            return AnalyzerFrame(PCD_TO_PICC_OUTPUT_TYPE, frame.start_time, frame.end_time, {"value": value})

        return None

    def decode_pcd_to_picc(self, raw_frame: bytes, valid_bits_of_last_byte: int) -> str:
        if valid_bits_of_last_byte == 7:
            if len(raw_frame) == 1:
                if raw_frame[0] == REQA:
                    return "REQA"
                if raw_frame[0] == WUPA:
                    return "WUPA"

        if valid_bits_of_last_byte != 8:
            return "???"
        if len(raw_frame) < 1:
            return "???"

        if raw_frame[0] == RATS:
            return "RATS"

        # min. 1 byte PCB + 2 byte crc
        if len(raw_frame) < (PCB_BYTE_SIZE + CRC_BYTE_SIZE):
            return "???"

        expected_crc = calc_iso14443a_crc(raw_frame[:-CRC_BYTE_SIZE])
        if expected_crc != raw_frame[-CRC_BYTE_SIZE:]:
            return "CRC-Error"

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
            return f"I({chaning_str}{cid_str}{nad_str}){block_nbr_str}: {inf.hex(' ').upper()}"
        if raw_frame[0] & PCB_R_BLOCK_MASK == PCB_R_BLOCK:
            if raw_frame[0] & PCB_R_ACK_NAK_MASK == PCB_R_ACK:
                return f"R(ACK{cid_str}){block_nbr_str}"
            if raw_frame[0] & PCB_R_ACK_NAK_MASK == PCB_R_NAK:
                return f"R(NAK{cid_str}){block_nbr_str}"
        if raw_frame[0] & PCB_S_BLOCK_MASK == PCB_S_BLOCK:
            if raw_frame[0] & PCB_S_DESELECT_MASK == PCB_S_DESELECT:
                return f"S(DESELECT{cid_str})"
            if raw_frame[0] & PCB_S_WTX_MASK == PCB_S_WTX:
                return f"S(WTX{cid_str}): {inf.hex(' ')}"
            if raw_frame[0] & PCB_S_PARAMETERS_MASK == PCB_S_PARAMETERS:
                return f"S(PARAMETERS{cid_str}): {inf.hex(' ').upper()}"

        return "???"
