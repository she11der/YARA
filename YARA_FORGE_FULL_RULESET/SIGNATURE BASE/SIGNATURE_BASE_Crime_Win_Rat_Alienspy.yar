rule SIGNATURE_BASE_Crime_Win_Rat_Alienspy : FILE
{
	meta:
		description = "Alien Spy Remote Access Trojan"
		author = "General Dynamics Fidelis Cybersecurity Solutions - Threat Research Team"
		id = "a79789cd-9b16-58f5-ab51-48bb900583d1"
		date = "2015-04-04"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_alienspy_rat.yar#L2-L50"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "2b6fec104a89badb057619f648119dcf6debd294ee2b80a1fde6ffa30a7a45f7"
		score = 75
		quality = 85
		tags = "FILE"
		reference_1 = "www.fidelissecurity.com/sites/default/files/FTA_1015_Alienspy_FINAL.pdf"
		reference_2 = "www.fidelissecurity.com/sites/default/files/AlienSpy-Configs2_1_2.csv"
		filetype = "Java"
		hash_1 = "075fa0567d3415fbab3514b8aa64cfcb"
		hash_2 = "818afea3040a887f191ee9d0579ac6ed"
		hash_3 = "973de705f2f01e82c00db92eaa27912c"
		hash_4 = "7f838907f9cc8305544bd0ad4cfd278e"
		hash_5 = "071e12454731161d47a12a8c4b3adfea"
		hash_6 = "a7d50760d49faff3656903c1130fd20b"
		hash_7 = "f399afb901fcdf436a1b2a135da3ee39"
		hash_8 = "3698a3630f80a632c0c7c12e929184fb"
		hash_9 = "fdb674cadfa038ff9d931e376f89f1b6"

	strings:
		$sa_1 = "META-INF/MANIFEST.MF"
		$sa_2 = "Main.classPK"
		$sa_3 = "plugins/Server.classPK"
		$sa_4 = "IDPK"
		$sb_1 = "config.iniPK"
		$sb_2 = "password.iniPK"
		$sb_3 = "plugins/Server.classPK"
		$sb_4 = "LoadStub.classPK"
		$sb_5 = "LoadStubDecrypted.classPK"
		$sb_7 = "LoadPassword.classPK"
		$sb_8 = "DecryptStub.classPK"
		$sb_9 = "ClassLoaders.classPK"
		$sc_1 = "config.xml"
		$sc_2 = "options"
		$sc_3 = "plugins"
		$sc_5 = "util/OSHelper"
		$sc_6 = "Start.class"
		$sc_7 = "AlienSpy"

	condition:
		uint16(0)==0x4B50 and filesize <800KB and (( all of ($sa_*)) or ( all of ($sb_*)) or ( all of ($sc_*)))
}