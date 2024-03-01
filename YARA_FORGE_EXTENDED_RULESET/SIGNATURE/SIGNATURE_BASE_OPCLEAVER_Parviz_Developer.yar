rule SIGNATURE_BASE_OPCLEAVER_Parviz_Developer
{
	meta:
		description = "Parviz developer known from Operation Cleaver"
		author = "Florian Roth (Nextron Systems)"
		id = "2bfa90a0-0495-5b21-98f7-5ed7ebc74b2d"
		date = "2014-12-02"
		modified = "2023-12-05"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_op_cleaver.yar#L318-L332"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "6ae043ee5baa7361def79811350317baf54eb76cf15001a7785808dc7947fddc"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Users\\parviz\\documents\\" nocase

	condition:
		$s1
}
