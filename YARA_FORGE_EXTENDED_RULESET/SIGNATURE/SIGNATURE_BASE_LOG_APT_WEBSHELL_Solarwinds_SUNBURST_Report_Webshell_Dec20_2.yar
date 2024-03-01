rule SIGNATURE_BASE_LOG_APT_WEBSHELL_Solarwinds_SUNBURST_Report_Webshell_Dec20_2
{
	meta:
		description = "Detects webshell access mentioned in FireEye's SUNBURST report"
		author = "Florian Roth (Nextron Systems)"
		id = "fb86164d-13de-5357-8f52-c597b51127ff"
		date = "2020-12-21"
		modified = "2023-12-05"
		reference = "https://www.guidepointsecurity.com/supernova-solarwinds-net-webshell-analysis/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_solarwinds_susp_sunburst.yar#L21-L32"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "ec52e244a483ace0f6932b553b159b23b767c00d1f64a4711e5f359832e846f5"
		score = 75
		quality = 85
		tags = ""

	strings:
		$xr1 = /logoimagehandler.ashx[^\n\s]{1,400}clazz=/ ascii wide

	condition:
		$xr1
}
