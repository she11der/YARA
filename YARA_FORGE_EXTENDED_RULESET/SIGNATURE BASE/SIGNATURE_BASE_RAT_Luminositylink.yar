rule SIGNATURE_BASE_RAT_Luminositylink
{
	meta:
		description = "Detects LuminosityLink RAT"
		author = "Kevin Breen <kevin@techanarchy.net>"
		id = "163fe10c-38a1-53d3-b3a5-4240229e0306"
		date = "2014-01-04"
		modified = "2023-12-05"
		reference = "http://malwareconfig.com/stats/LuminosityLink"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_rats_malwareconfig.yar#L467-L493"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "5e70e3e0885d098f1ac2bcc324cd8ad2682fbfc395f189cabc4a4f97a0109682"
		score = 75
		quality = 60
		tags = ""
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "SMARTLOGS" wide
		$b = "RUNPE" wide
		$c = "b.Resources" wide
		$d = "CLIENTINFO*" wide
		$e = "Invalid Webcam Driver Download URL, or Failed to Download File!" wide
		$f = "Proactive Anti-Malware has been manually activated!" wide
		$g = "REMOVEGUARD" wide
		$h = "C0n1f8" wide
		$i = "Luminosity" wide
		$j = "LuminosityCryptoMiner" wide
		$k = "MANAGER*CLIENTDETAILS*" wide

	condition:
		all of them
}
