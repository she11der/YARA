rule SIGNATURE_BASE_Stealthwasp_S_Basic_Portscanner_V1_2
{
	meta:
		description = "Auto-generated rule on file StealthWasp's Basic PortScanner v1.2.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		id = "7f706186-f2e2-5d4d-951a-2ec8fc757cec"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-hacktools.yar#L396-L407"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "7c0f2cab134534cd35964fe4c6a1ff00"
		logic_hash = "b01c165b5e5be3ba6905e8bc44a14c3d7195effd058e4c0c31678777d19db8b5"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = "Basic PortScanner"
		$s6 = "Now scanning port:"

	condition:
		all of them
}