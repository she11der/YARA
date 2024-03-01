rule SIGNATURE_BASE_WEBSHELL_CVE_2021_27065_Webshells : CVE_2021_27065 FILE
{
	meta:
		description = "Detects web shells dropped by CVE-2021-27065. All actors, not specific to HAFNIUM. TLP:WHITE"
		author = "Joe Hannon, Microsoft Threat Intelligence Center (MSTIC)"
		id = "27677f35-24a3-59cc-a3ad-b83884128da7"
		date = "2021-03-05"
		modified = "2023-12-05"
		reference = "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_hafnium.yar#L182-L200"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "71795ba67bc8a4cea06b93da34b6291029ff74b200e37eb66f6ac51a6ff194cd"
		score = 75
		quality = 61
		tags = "CVE-2021-27065, FILE"

	strings:
		$script1 = "script language" ascii wide nocase
		$script2 = "page language" ascii wide nocase
		$script3 = "runat=\"server\"" ascii wide nocase
		$script4 = "/script" ascii wide nocase
		$externalurl = "externalurl" ascii wide nocase
		$internalurl = "internalurl" ascii wide nocase
		$internalauthenticationmethods = "internalauthenticationmethods" ascii wide nocase
		$extendedprotectiontokenchecking = "extendedprotectiontokenchecking" ascii wide nocase

	condition:
		filesize <50KB and any of ($script*) and ($externalurl or $internalurl) and $internalauthenticationmethods and $extendedprotectiontokenchecking
}
