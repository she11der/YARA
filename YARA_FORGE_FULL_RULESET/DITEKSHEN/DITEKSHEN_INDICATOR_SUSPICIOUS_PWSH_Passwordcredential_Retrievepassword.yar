import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_PWSH_Passwordcredential_Retrievepassword
{
	meta:
		description = "Detects PowerShell content designed to retrieve passwords from host"
		author = "ditekSHen"
		id = "b34599ab-b874-5ea5-990d-bc7593bb08b5"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L1046-L1056"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "f09320d9c4734579a535c7fee993fa076974b13ffd25e0d9ab02bc09663595f8"
		score = 40
		quality = 39
		tags = ""
		importance = 20

	strings:
		$namespace = "Windows.Security.Credentials.PasswordVault" ascii wide nocase
		$method1 = "RetrieveAll()" ascii wide nocase
		$method2 = ".RetrievePassword()" ascii wide nocase

	condition:
		$namespace and 1 of ($method*)
}
