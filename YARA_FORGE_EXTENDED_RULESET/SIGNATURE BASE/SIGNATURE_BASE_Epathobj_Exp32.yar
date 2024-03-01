rule SIGNATURE_BASE_Epathobj_Exp32 : FILE
{
	meta:
		description = "Chinese Hacktool Set - file epathobj_exp32.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "ca4639af-ee4f-5220-9595-e7a06b9a8534"
		date = "2015-06-13"
		modified = "2022-12-21"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L1217-L1235"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "ed86ff44bddcfdd630ade8ced39b4559316195ba"
		logic_hash = "8959837257848a08240d0423971b9d3a850a7e9cc796de2c9b2d34814923f8ec"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Watchdog thread %d waiting on Mutex" fullword ascii
		$s1 = "Exploit ok run command" fullword ascii
		$s2 = "\\epathobj_exp\\Release\\epathobj_exp.pdb" ascii
		$s3 = "Alllocated userspace PATHRECORD () %p" fullword ascii
		$s4 = "Mutex object did not timeout, list not patched" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <270KB and all of them
}
