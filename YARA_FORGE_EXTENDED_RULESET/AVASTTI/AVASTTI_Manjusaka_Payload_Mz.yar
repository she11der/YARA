rule AVASTTI_Manjusaka_Payload_Mz
{
	meta:
		description = "No description has been set in the source file - AvastTI"
		author = "Avast Threat Intel Team"
		id = "808fe840-27e2-5361-b97a-4b04e6d8f7da"
		date = "2022-10-05"
		modified = "2022-10-05"
		reference = "https://github.com/avast/ioc"
		source_url = "https://github.com/avast/ioc/blob/b515ef8c40e107f0cb519789bc1c5be5bdcb9d6b/Manjusaka/Manjusaka.yar#L124-L161"
		license_url = "N/A"
		hash = "6839180bc3a2404e629c108d7e8c8548caf9f8249bbbf658b47c00a15a64758f"
		hash = "cd0c75638724c0529cc9e7ca0a91d2f5d7221ef2a87b65ded2bc1603736e3b5d"
		hash = "d5918611b1837308d0c6d19bff4b81b00d4f6a30c1240c00a9e0a9b08dde1412"
		hash = "2b174d417a4e43fd6759c64512faa88f4504e8f14f08fd5348fff51058c9958f"
		hash = "377bacba69d2bec770599ab21a202b574b92fb431fc35bbdf39080025d6cf2d6"
		hash = "86c633467ba7981d3946a63184dbfabce587b571f761b3eb1e3e43f6b1df6f2c"
		hash = "51857882d1202e72c0cf18ff21de773c2a31ee68ff28385f968478401c5ab4bb"
		hash = "e07aa10f19574a856a4ac389a3ded96f2d78f41f939935dd678811bd12b5bd03"
		hash = "9e7144540430d97de38a2adcef16ad43e23c91281462b135fcc56cafc2f34160"
		logic_hash = "81b01eff8384707ce67f6d888e59e690d7fb7b4e32359043ced9230499813aa7"
		score = 60
		quality = 50
		tags = ""

	strings:
		$s01 = ".\\protos\\cs.rstargetintranethostnameplatformpidAgentsstatusagentinternetupdateatAgentUpdate"
		$s02 = "PluginExecPluginLoadReqCwdcmdReqCmd"
		$s03 = "Users\\Administrator.WIN7-2021OVWRCZ\\.cargo"
		$s04 = "Users\\runneradmin\\.cargo"
		$s05 = "windows\\c.rsNtReadFile"
		$s11 = "src\\mirrors.ustc.edu.cn-"
		$s12 = "CodeProject\\hw_src\\NPSC2\\npc\\target\\release\\deps\\npc.pdb"
		$s13 = "@@@manjusaka"
		$s14 = "***manjusakahttp://"
		$s15 = "SELECT signon_realm, username_value, password_value FROM loginsnetshwlanshowprofile"
		$s16 = "name=key=clearWIFI"
		$s17 = "cmd.exe/c"
		$s18 = "Accept-Languagezh-CN,zh;q=0.9,en;q=0.8Accept-Encodinggzip"
		$s19 = "library\\std\\src\\sys_common\\wtf8.rs"
		$s110 = "plug_getpass_nps.dll"
		$s111 = "plug_test_nps.dll"

	condition:
		AVASTTI_EXE_PRIVATE and (2 of ($s0*) or 3 of ($s1*))
}
