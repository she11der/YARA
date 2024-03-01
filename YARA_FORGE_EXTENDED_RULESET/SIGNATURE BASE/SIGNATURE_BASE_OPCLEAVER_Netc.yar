rule SIGNATURE_BASE_OPCLEAVER_Netc
{
	meta:
		description = "Net Crawler used by attackers in Operation Cleaver"
		author = "Cylance Inc."
		id = "68f32662-0d7d-5dfa-8bfd-ca41d383e19c"
		date = "2014-12-02"
		modified = "2023-12-05"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_op_cleaver.yar#L52-L66"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "7da739c33da91f07e9e35ceab88a37477372998b4cf4b692b8d26cd1a4d936de"
		score = 70
		quality = 85
		tags = ""

	strings:
		$s1 = "NetC.exe" wide
		$s2 = "Net Service"

	condition:
		all of them
}
