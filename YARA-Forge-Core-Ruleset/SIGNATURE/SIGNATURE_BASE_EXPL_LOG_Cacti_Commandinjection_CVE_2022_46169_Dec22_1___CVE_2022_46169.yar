rule SIGNATURE_BASE_EXPL_LOG_Cacti_Commandinjection_CVE_2022_46169_Dec22_1___CVE_2022_46169
{
	meta:
		description = "Detects potential exploitation attempts that target the Cacti Command Injection CVE-2022-46169"
		author = "Nasreddine Bencherchali"
		id = "c799a419-87ed-55ea-8ebb-d4da901be4ad"
		date = "2022-12-27"
		modified = "2023-12-05"
		reference = "https://github.com/Cacti/cacti/security/advisories/GHSA-6p93-p743-35gf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/expl_cve_2022_46169_cacti.yar#L1-L13"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "6ccd3b830deb5c5d65519274c4c528203a2a14a177382334da87e288174e2cfe"
		score = 70
		quality = 85
		tags = "CVE-2022-46169"

	strings:
		$xr1 = /\/remote_agent\.php.{1,300}(whoami|\/bin\/bash|\/bin\/sh|\bwget\b|powershell|cmd \/c|cmd\.exe \/c).{1,300} 200 / ascii

	condition:
		$xr1
}