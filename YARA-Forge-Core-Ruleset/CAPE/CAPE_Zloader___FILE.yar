rule CAPE_Zloader___FILE
{
	meta:
		description = "Zloader Payload"
		author = "kevoreilly"
		id = "83223afc-162c-565c-8288-705722daa64a"
		date = "2021-02-17"
		modified = "2021-02-17"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/5db57762ada4ddb5b47cdb2c13150917f53241c0/data/yara/CAPE/Zloader.yar#L1-L12"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/5db57762ada4ddb5b47cdb2c13150917f53241c0/LICENSE"
		logic_hash = "0cc8a3128e8d81e7dd8eb23f968458ffb06d8c7368ee4747972e3a45945cd75f"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "Zloader Payload"

	strings:
		$rc4_init = {31 [1-3] 66 C7 8? 00 01 00 00 00 00 90 90 [0-5] 8? [5-90] 00 01 00 00 [0-15] (74|75)}
		$decrypt_conf = {83 C4 04 84 C0 74 5? E8 [4] E8 [4] E8 [4] E8 [4] ?8 [4] ?8 [4] ?8}

	condition:
		uint16(0)==0x5A4D and any of them
}