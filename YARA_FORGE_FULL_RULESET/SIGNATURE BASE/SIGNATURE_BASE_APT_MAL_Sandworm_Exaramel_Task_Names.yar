rule SIGNATURE_BASE_APT_MAL_Sandworm_Exaramel_Task_Names
{
	meta:
		description = "Detects names of the tasks received from the CC server in Exaramel malware"
		author = "FR/ANSSI/SDO"
		id = "185f2f3b-bf5c-54af-bca2-400d08bf9c91"
		date = "2021-02-15"
		modified = "2023-12-05"
		reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_sandworm_centreon.yar#L148-L167"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "193482da1e2b9509fa9c65d46edc56057f7b5d44b7408d918d4a9cbb60736dab"
		score = 80
		quality = 85
		tags = ""

	strings:
		$ = "App.Delete"
		$ = "App.SetServer"
		$ = "App.SetProxy"
		$ = "App.SetTimeout"
		$ = "App.Update"
		$ = "IO.ReadFile"
		$ = "IO.WriteFile"
		$ = "OS.ShellExecute"

	condition:
		all of them
}
