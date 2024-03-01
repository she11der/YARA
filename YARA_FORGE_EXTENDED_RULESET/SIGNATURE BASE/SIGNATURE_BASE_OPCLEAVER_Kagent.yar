rule SIGNATURE_BASE_OPCLEAVER_Kagent
{
	meta:
		description = "Backdoor used by attackers in Operation Cleaver"
		author = "Cylance Inc."
		id = "32d20495-eeed-5b2b-915d-cad60fa991f6"
		date = "2014-12-02"
		modified = "2023-12-05"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_op_cleaver.yar#L190-L204"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "bd72ade7d40db830dc980def5107261f9cb41b713f9a0a1b2f41f7658b31653e"
		score = 70
		quality = 85
		tags = ""

	strings:
		$s1 = "kill command is in last machine, going back"
		$s2 = "message data length in B64: %d Bytes"

	condition:
		all of them
}
