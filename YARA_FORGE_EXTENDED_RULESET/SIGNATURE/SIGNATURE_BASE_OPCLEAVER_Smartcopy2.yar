rule SIGNATURE_BASE_OPCLEAVER_Smartcopy2
{
	meta:
		description = "Malware or hack tool used by attackers in Operation Cleaver"
		author = "Cylance Inc."
		id = "898d9060-208a-5dfb-a452-50ab49b80a9d"
		date = "2014-12-02"
		modified = "2023-12-05"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_op_cleaver.yar#L84-L98"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "5b83588fa80558cd387511d38e9d1c51c488216b9cd27e848d8bdc59cd8ce348"
		score = 70
		quality = 85
		tags = ""

	strings:
		$s1 = "SmartCopy2.Properties"
		$s2 = "ZhuFrameWork"

	condition:
		all of them
}
