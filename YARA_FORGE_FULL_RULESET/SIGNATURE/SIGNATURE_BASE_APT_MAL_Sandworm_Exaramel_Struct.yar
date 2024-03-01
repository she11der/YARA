rule SIGNATURE_BASE_APT_MAL_Sandworm_Exaramel_Struct
{
	meta:
		description = "Detects the beginning of type _type struct for some of the most important structs in Exaramel malware"
		author = "FR/ANSSI/SDO"
		id = "8282e485-966c-554d-8e41-70dc1657f5ea"
		date = "2021-02-15"
		modified = "2023-12-05"
		reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_sandworm_centreon.yar#L169-L185"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "312d0598fa85837f94023036468fcae50e8b2de532430a944befa8090afe79f6"
		score = 80
		quality = 85
		tags = ""

	strings:
		$struct_le_config = {70 00 00 00 00 00 00 00 58 00 00 00 00 00 00 00 47 2d 28 42 0? [2] 19}
		$struct_le_worker = {30 00 00 00 00 00 00 00 30 00 00 00 00 00 00 00 46 6a 13 e2 0? [2] 19}
		$struct_le_client = {20 00 00 00 00 00 00 00 10 00 00 00 00 00 00 00 7b 6a 49 84 0? [2] 19}
		$struct_le_report = {30 00 00 00 00 00 00 00 28 00 00 00 00 00 00 00 bf 35 0d f9 0? [2] 19}
		$struct_le_task = {50 00 00 00 00 00 00 00 20 00 00 00 00 00 00 00 88 60 a1 c5 0? [2] 19}

	condition:
		any of them
}
