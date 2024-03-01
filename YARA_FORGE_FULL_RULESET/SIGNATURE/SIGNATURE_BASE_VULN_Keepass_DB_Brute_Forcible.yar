rule SIGNATURE_BASE_VULN_Keepass_DB_Brute_Forcible : FILE
{
	meta:
		description = "Detects KeePass .kdbx password stores, which could be brute forced to steal the credentials. With AES-KDF and less than 65536 iterations the cracking speed with a single GPU is 20k/s, for the old default of 6.000 iterations it's 200k/s. Best remediation is to change the key derivative function to Argon2d and delete all older versions of the .kdbx"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "b1a86e03-b3d1-5abc-9287-a4846451caff"
		date = "2023-07-20"
		modified = "2023-12-05"
		reference = "https://keepass.info/help/base/security.html#secdictprotect"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/vuln_keepass_brute_forcible.yar#L2-L17"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "14460f7d4976a3bbd6de2f7cfccfbfec35eb780ab762396a6490669ddde59ce8"
		score = 60
		quality = 85
		tags = "FILE"

	strings:
		$keepass_magic = { 03 D9 A2 9A 67 FB 4B B5 }
		$below_65536_rounds = { 06 08 00 ?? ?? 00 00 00 00 00 00 07 10 00 }

	condition:
		$keepass_magic at 0 and $below_65536_rounds at 108
}
