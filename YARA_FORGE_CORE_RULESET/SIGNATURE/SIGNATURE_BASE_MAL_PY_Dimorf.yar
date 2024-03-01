import "pe"

rule SIGNATURE_BASE_MAL_PY_Dimorf
{
	meta:
		description = "Detection for Dimorf ransomeware"
		author = "Silas Cutler"
		id = "78b53433-6926-58cd-8ec0-2195af803aab"
		date = "2023-01-03"
		modified = "2023-12-05"
		reference = "https://github.com/Ort0x36/Dimorf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_100days_of_yara_2023.yar#L224-L242"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "7499b21f77d07364983b94134a60f7c99e71a5392386437d459a196bf71852fb"
		score = 75
		quality = 85
		tags = ""
		version = "1.0"

	strings:
		$func01 = "def find_and_encrypt"
		$func02 = "def check_os"
		$comment01 = "checks if the user has permission on the file."
		$misc01 = "log_dimorf.log"
		$misc02 = ".dimorf"

	condition:
		all of them
}
