import "pe"

rule SIGNATURE_BASE_APT_NK_Tradingtech_Forensicartifacts_Apr23_1 : FILE
{
	meta:
		description = "Detects forensic artifacts, file names and keywords related the Trading Technologies compromise UNC4736"
		author = "Florian Roth"
		id = "f79a5321-4f22-52d9-aa83-4aa750ecc036"
		date = "2023-04-20"
		modified = "2023-04-21"
		reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_nk_tradingtech_apr23.yar#L204-L225"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "50329427e56b70335a12f0dde87a36ac95838377482eebab334d252332fe481b"
		score = 60
		quality = 85
		tags = "FILE"

	strings:
		$x1 = "www.tradingtechnologies.com/trading/order-management" ascii wide
		$xf1 = "X_TRADER_r7.17.90p608.exe" ascii wide
		$xf2 = "\\X_TRADER-ja.mst" ascii wide
		$xf3 = "C:\\Programdata\\TPM\\TpmVscMgrSvr.exe" ascii wide
		$xf4 = "C:\\Programdata\\TPM\\winscard.dll" ascii wide
		$fp1 = "<html"

	condition:
		not uint16(0)==0x5025 and 1 of ($x*) and not 1 of ($fp*)
}
