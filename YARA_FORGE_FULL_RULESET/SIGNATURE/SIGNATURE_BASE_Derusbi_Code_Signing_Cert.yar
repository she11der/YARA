rule SIGNATURE_BASE_Derusbi_Code_Signing_Cert : FILE
{
	meta:
		description = "Detects an executable signed with a certificate also used for Derusbi Trojan - suspicious"
		author = "Florian Roth (Nextron Systems)"
		id = "d123fde9-0182-5232-a716-b76e8d9830c4"
		date = "2015-12-15"
		modified = "2023-12-05"
		reference = "http://blog.airbuscybersecurity.com/post/2015/11/Newcomers-in-the-Derusbi-family"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_derusbi.yar#L81-L96"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "dae976a4896a4f6b6a1b415582db84f3da5aac03bf4079f75e11c790dcf23900"
		score = 60
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Fuqing Dawu Technology Co.,Ltd.0" fullword ascii
		$s2 = "XL Games Co.,Ltd.0" fullword ascii
		$s3 = "Wemade Entertainment co.,Ltd0" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <800KB and 1 of them
}
