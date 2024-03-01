rule TRELLIX_ARC_Apt_Blackenergy_Pdb : TROJAN FILE
{
	meta:
		description = "Rule to detect the BlackEnergy trojan"
		author = "Marc Rivero | McAfee ATR Team"
		id = "55c96b66-a8bf-5390-a75a-f3d2441c2a55"
		date = "2013-02-15"
		modified = "2020-08-14"
		reference = "https://www.kaspersky.com.au/resource-center/threats/blackenergy"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/APT/APT_blackenergy_pdb.yar#L1-L38"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "4b2efcda5269f4b80dc417a2b01332185f2fafabd8ba7114fa0306baaab5a72d"
		logic_hash = "7bb85d03d8f2a4d91554f7fea96e9bbe36b153cfa4a91fd13fb99d41d430c9e9"
		score = 75
		quality = 70
		tags = "TROJAN, FILE"
		rule_version = "v1"
		malware_type = "trojan"
		malware_family = "Trojan:W32/BlackEngergy"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$s1 = "msiexec.exe /i \"%s\" %s REBOOT=\"ReallySuppress\"" fullword wide
		$s2 = "InstallUpdate: CreateProcess failed, Cmdline=%s Error=%d ." fullword wide
		$s3 = "Portuguese=Instalando o Tempo de Execu" fullword wide
		$s4 = "Initialization: Failed to initialize - Unable to get Upgrade Code." fullword wide
		$s5 = "This version of Internet Explorer is not supported.  You should upgrade Internet Explorer to version %s and run setup again.  Se" wide
		$s6 = "Initialization: Failed to open %s file, Make sure the file is not used by another process." fullword wide
		$s7 = "o %s e execute a configura" fullword wide
		$s8 = "Initialization: Failed to initialize - Unable to get Product Version." fullword wide
		$s9 = "f:\\CB\\11X_Security\\Acrobat\\Installers\\BootStrapExe_Small\\Release\\Setup.pdb" fullword ascii
		$s10 = "BootStrap.log" fullword wide
		$s11 = "ACDownloaderDlg" fullword ascii
		$s12 = "Initialization: Failed to initialize Product - msi key not specified." fullword wide
		$s13 = "rio atualizar para o Service Pack %s e executar a instala" fullword wide
		$s14 = "\\Msi.dll" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and all of them
}
