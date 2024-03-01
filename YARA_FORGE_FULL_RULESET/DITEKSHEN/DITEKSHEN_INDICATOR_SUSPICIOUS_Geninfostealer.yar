import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_Geninfostealer : FILE
{
	meta:
		description = "Detects executables containing common artifacts observed in infostealers"
		author = "ditekSHen"
		id = "531d8f7f-dee5-5d05-9293-f1ab5d5ac780"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L630-L657"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "f9e6f6b470e010d362db55fcf563f85a3a408ef8331c04a157f2676442b63b1a"
		score = 40
		quality = 31
		tags = "FILE"
		importance = 20

	strings:
		$f1 = "FileZilla\\recentservers.xml" ascii wide
		$f2 = "FileZilla\\sitemanager.xml" ascii wide
		$f3 = "SOFTWARE\\\\Martin Prikryl\\\\WinSCP 2\\\\Sessions" ascii wide
		$b1 = "Chrome\\User Data\\" ascii wide
		$b2 = "Mozilla\\Firefox\\Profiles" ascii wide
		$b3 = "Software\\Microsoft\\Internet Explorer\\IntelliForms\\Storage2" ascii wide
		$b4 = "Opera Software\\Opera Stable\\Login Data" ascii wide
		$b5 = "YandexBrowser\\User Data\\" ascii wide
		$s1 = "key3.db" nocase ascii wide
		$s2 = "key4.db" nocase ascii wide
		$s3 = "cert8.db" nocase ascii wide
		$s4 = "logins.json" nocase ascii wide
		$s5 = "account.cfn" nocase ascii wide
		$s6 = "wand.dat" nocase ascii wide
		$s7 = "wallet.dat" nocase ascii wide
		$a1 = "username_value" ascii wide
		$a2 = "password_value" ascii wide
		$a3 = "encryptedUsername" ascii wide
		$a4 = "encryptedPassword" ascii wide
		$a5 = "httpRealm" ascii wide

	condition:
		uint16(0)==0x5a4d and ((2 of ($f*) and 2 of ($b*) and 1 of ($s*) and 3 of ($a*)) or (14 of them ))
}
