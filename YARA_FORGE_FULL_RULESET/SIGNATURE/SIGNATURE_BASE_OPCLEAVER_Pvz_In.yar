rule SIGNATURE_BASE_OPCLEAVER_Pvz_In
{
	meta:
		description = "Parviz tool used by attackers in Operation Cleaver"
		author = "Cylance Inc."
		id = "dede12b3-f1dd-58ba-a860-829b2331b740"
		date = "2014-12-02"
		modified = "2023-12-05"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_op_cleaver.yar#L222-L236"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "eae778162be5dcfa0005bb237c5209e7103db3549e06706744f9ebdf04e192df"
		score = 70
		quality = 85
		tags = ""

	strings:
		$s1 = "LAST_TIME=00/00/0000:00:00PM$"
		$s2 = "if %%ERRORLEVEL%% == 1 GOTO line"

	condition:
		all of them
}
