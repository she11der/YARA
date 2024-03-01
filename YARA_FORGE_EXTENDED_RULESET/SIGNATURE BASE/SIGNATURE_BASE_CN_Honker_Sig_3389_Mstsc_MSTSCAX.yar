rule SIGNATURE_BASE_CN_Honker_Sig_3389_Mstsc_MSTSCAX : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file MSTSCAX.DLL"
		author = "Florian Roth (Nextron Systems)"
		id = "9508b613-f897-5277-97e0-30e36fb5d747"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L1245-L1261"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "2fa006158b2d87b08f1778f032ab1b8e139e02c6"
		logic_hash = "2bfe10ec4af5d0f32fc03714c0cb01d9b0d446daa67cc0cce0b83f6a57e7c5a5"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "ResetPasswordWWWx" fullword ascii
		$s2 = "Terminal Server Redirected Printer Doc" fullword wide
		$s3 = "Cleaning temp directory" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and all of them
}
