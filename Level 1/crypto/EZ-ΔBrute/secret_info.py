k = bytes.fromhex("00112233445566778899aabbccddeeff")
k_prime = bytes.fromhex("ffeeddccbbaa99887766554433221100")
# "FAKEFLAG" is not a valid hex string.
# You can use a direct byte string or a hex-encoded one.
FLAG_BLOCK = b"FAKEFLAG"
# For local testing, define the flag as a byte string.
REAL_FLAG = b"DH{Railway_Prob_Was_Most_Solved_Prob_In_KUCIS_CTF_96b777e3fee5fe7b7c54ea628d2fc32f_ed05d8c1b63c546b1e934e637bd6792408b24bb1d83a30af2d6656ec2d138399}"