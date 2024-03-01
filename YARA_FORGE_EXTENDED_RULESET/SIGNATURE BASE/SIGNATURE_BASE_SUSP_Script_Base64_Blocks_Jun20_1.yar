rule SIGNATURE_BASE_SUSP_Script_Base64_Blocks_Jun20_1
{
	meta:
		description = "Detects suspicious file with base64 encoded payload in blocks"
		author = "Florian Roth (Nextron Systems)"
		id = "cef759a5-b02a-53e7-bf27-184eee6bc3fa"
		date = "2020-06-05"
		modified = "2023-12-05"
		reference = "https://posts.specterops.io/covenant-v0-5-eee0507b85ba"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_susp_obfuscation.yar#L70-L83"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "7d456cbbbd76f543afe144a2876a02db834aa6b09ecd4d6aa2f25ce8eeac5de8"
		score = 70
		quality = 85
		tags = ""

	strings:
		$sa1 = "<script language=" ascii
		$sb2 = { 41 41 41 22 2B 0D 0A 22 41 41 41 }

	condition:
		all of them
}
