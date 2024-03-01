rule SIGNATURE_BASE_SUSP_Putty_Unnormal_Size : FILE
{
	meta:
		description = "Detects a putty version with a size different than the one provided by Simon Tatham (could be caused by an additional signature or malware)"
		author = "Florian Roth (Nextron Systems)"
		id = "576b118c-d4be-5ce2-994a-ce3f943dda88"
		date = "2019-01-07"
		modified = "2022-06-30"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/generic_anomalies.yar#L442-L492"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "2f2c21cc25eaba8c1812db617203427a59e9a55f8620676e4bbe4cb3cd4071fd"
		score = 50
		quality = 85
		tags = "FILE"
		hash1 = "e5e89bdff733d6db1cffe8b3527e823c32a78076f8eadc2f9fd486b74a0e9d88"
		hash2 = "ce4c1b718b54973291aefdd63d1cca4e4d8d4f5353a2be7f139a290206d0c170"
		hash3 = "adb72ea4eab7b2efc2da6e72256b5a3bb388e9cdd4da4d3ff42a9fec080aa96f"
		hash4 = "1c0bd6660fa43fa90bd88b56cdd4a4c2ffb4ef9d04e8893109407aa7039277db"

	strings:
		$s1 = "SSH, Telnet and Rlogin client" fullword wide
		$v1 = "Release 0.6" wide
		$v2 = "Release 0.70" wide
		$fp1 = "KiTTY fork" fullword wide

	condition:
		uint16(0)==0x5a4d and $s1 and 1 of ($v*) and not 1 of ($fp*) and filesize !=524288 and filesize !=495616 and filesize !=483328 and filesize !=524288 and filesize !=712176 and filesize !=828400 and filesize !=569328 and filesize !=454656 and filesize !=531368 and filesize !=524288 and filesize !=483328 and filesize !=713592 and filesize !=829304 and filesize !=571256 and filesize !=774200 and filesize !=854072 and filesize !=665144 and filesize !=774200 and filesize !=854072 and filesize !=665144 and filesize !=640000 and filesize !=650720 and filesize !=662808 and filesize !=651256 and filesize !=664432
}
