rule SIGNATURE_BASE_Dos_1 : FILE
{
	meta:
		description = "Chinese Hacktool Set - file 1.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "3f1cc1b3-bce2-5a29-849e-ee7deb5e8809"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L333-L347"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "b554f0687a12ec3a137f321cc15e052ff219f28c"
		logic_hash = "d4cf3e738743e5402602e045cf590b969dca2d6f7f1bdd57cc398df3392560d9"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "/churrasco/-->Usage: Churrasco.exe \"command to run\"" fullword ascii
		$s2 = "/churrasco/-->Done, command should have ran as SYSTEM!" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and all of them
}
