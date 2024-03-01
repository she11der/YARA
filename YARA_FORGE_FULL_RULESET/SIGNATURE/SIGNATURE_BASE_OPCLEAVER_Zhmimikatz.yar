rule SIGNATURE_BASE_OPCLEAVER_Zhmimikatz
{
	meta:
		description = "Mimikatz wrapper used by attackers in Operation Cleaver"
		author = "Cylance Inc."
		id = "fba8ab6e-3b61-53a1-b4df-178442e3cf24"
		date = "2014-12-02"
		modified = "2023-12-05"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_op_cleaver.yar#L302-L316"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "1d6ce5b3351d4b01abe0c2f614d002d4e96599b4bfa01138704a3fdf345d0786"
		score = 70
		quality = 85
		tags = ""

	strings:
		$s1 = "MimikatzRunner"
		$s2 = "zhmimikatz"

	condition:
		all of them
}
