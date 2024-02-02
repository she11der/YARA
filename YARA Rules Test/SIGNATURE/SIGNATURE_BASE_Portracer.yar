rule SIGNATURE_BASE_Portracer
{
	meta:
		description = "Auto-generated rule on file PortRacer.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		id = "54717938-2f4c-5442-b0ad-40b9acd1101a"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-hacktools.yar#L288-L300"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "2834a872a0a8da5b1be5db65dfdef388"
		logic_hash = "f6ad85a8970b10e25becca76e17bff30cbc787ed45f331af4ecf9563ff11b65d"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "Auto Scroll BOTH Text Boxes"
		$s4 = "Start/Stop Portscanning"
		$s6 = "Auto Save LogFile by pressing STOP"

	condition:
		all of them
}