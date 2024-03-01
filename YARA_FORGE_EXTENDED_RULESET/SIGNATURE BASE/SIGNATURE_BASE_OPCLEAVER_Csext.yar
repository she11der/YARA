rule SIGNATURE_BASE_OPCLEAVER_Csext
{
	meta:
		description = "Backdoor used by attackers in Operation Cleaver"
		author = "Cylance Inc."
		id = "f865eae5-9988-5533-a004-e1694761a557"
		date = "2014-12-02"
		modified = "2023-12-05"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_op_cleaver.yar#L173-L188"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "b4d070b71b685608ab84e757d01293749f2c017a6cd5b6ade6591264adc9836b"
		score = 70
		quality = 85
		tags = ""

	strings:
		$s1 = "COM+ System Extentions"
		$s2 = "csext.exe"
		$s3 = "COM_Extentions_bin"

	condition:
		all of them
}
