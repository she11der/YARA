rule SIGNATURE_BASE_CN_APT_Zerot_Nflogger : FILE
{
	meta:
		description = "Chinese APT by Proofpoint ZeroT RAT  - file nflogger.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "0d23f312-e3b6-5c23-855b-25ae54265512"
		date = "2017-02-04"
		modified = "2023-12-05"
		reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_cn_pp_zerot.yar#L165-L178"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "dc9b19e3c4c321cb9f840ec9ff78bec9e4a075cc62ea2823d92a3fbd9f99cc07"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "946adbeb017616d56193a6d43fe9c583be6ad1c7f6a22bab7df9db42e6e8ab10"

	strings:
		$x1 = "\\LoaderDll.VS2010\\Release\\" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and all of them )
}
