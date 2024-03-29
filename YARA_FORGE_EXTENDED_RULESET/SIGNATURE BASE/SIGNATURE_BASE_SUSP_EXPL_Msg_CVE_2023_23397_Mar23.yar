rule SIGNATURE_BASE_SUSP_EXPL_Msg_CVE_2023_23397_Mar23 : CVE_2023_23397 FILE
{
	meta:
		description = "MSG file with a PidLidReminderFileParameter property, potentially exploiting CVE-2023-23397"
		author = "delivr.to, modified by Florian Roth, Nils Kuhnert, Arnim Rupp, marcin@ulikowski.pl"
		id = "0a4d7bbe-1e17-5240-ad0f-29511752b267"
		date = "2023-03-15"
		modified = "2023-03-17"
		reference = "https://www.mdsec.co.uk/2023/03/exploiting-cve-2023-23397-microsoft-outlook-elevation-of-privilege-vulnerability/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/expl_outlook_cve_2023_23397.yar#L1-L37"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "47fee24586cd2858cfff2dd7a4e76dc95eb44c8506791ccc2d59c837786eafe3"
		hash = "582442ee950d546744f2fa078adb005853a453e9c7f48c6c770e6322a888c2cf"
		hash = "6c0087a5cbccb3c776a471774d1df10fe46b0f0eb11db6a32774eb716e1b7909"
		hash = "7fb7a2394e03cc4a9186237428a87b16f6bf1b66f2724aea1ec6a56904e5bfad"
		hash = "eedae202980c05697a21a5c995d43e1905c4b25f8ca2fff0c34036bc4fd321fa"
		logic_hash = "35c0dd37f5f563fe2cf583f71391006309c1d8843a3a71004e92c9a9d2248494"
		score = 60
		quality = 85
		tags = "CVE-2023-23397, FILE"

	strings:
		$psetid_app = { 02 20 06 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
		$psetid_meeting = { 90 DA D8 6E 0B 45 1B 10 98 DA 00 AA 00 3F 13 05 }
		$psetid_task = { 03 20 06 00 00 00 00 00 c0 00 00 00 00 00 00 46 }
		$rfp = { 1F 85 00 00 }
		$u1 = { 00 00 5C 00 5C 00 }
		$fp_msi1 = {84 10 0C 00 00 00 00 00 C0 00 00 00 00 00 00 46}

	condition:
		uint32be(0)==0xD0CF11E0 and uint32be(4)==0xA1B11AE1 and 1 of ($psetid*) and $rfp and $u1 and not 1 of ($fp*)
}
