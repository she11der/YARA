import "pe"

rule SIGNATURE_BASE_IMPLANT_4_V3_Alternativerule : HIGHVOL FILE
{
	meta:
		description = "Detects a group of different malware samples"
		author = "Florian Roth (Nextron Systems)"
		id = "47e9028b-7718-5372-8a1a-94c208c29ed4"
		date = "2017-02-12"
		modified = "2023-12-05"
		reference = "US CERT Grizzly Steppe Report"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_grizzlybear_uscert.yar#L788-L803"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "35468f7699b96fcaaaa032eef7dae34ec314e9c652f9f8b2e8ca7343fb5cec50"
		score = 75
		quality = 85
		tags = "FILE"
		comment = "Alternative rule - not based on the original samples but samples on which the original rule matched"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "2244fe9c5d038edcb5406b45361613cf3909c491e47debef35329060b00c985a"

	strings:
		$op1 = { 33 c9 41 ff 13 13 c9 ff 13 72 f8 c3 53 1e 01 00 }
		$op2 = { 21 da 40 00 00 a0 40 00 08 a0 40 00 b0 70 40 00 }

	condition:
		( uint16(0)==0x5a4d and all of them )
}
