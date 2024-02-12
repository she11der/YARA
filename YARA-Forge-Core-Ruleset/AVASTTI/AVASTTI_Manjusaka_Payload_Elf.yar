rule AVASTTI_Manjusaka_Payload_Elf
{
	meta:
		description = "No description has been set in the source file - AvastTI"
		author = "Avast Threat Intel Team"
		id = "010398f6-ca9b-58b4-a9d8-12428f649ffc"
		date = "2022-10-05"
		modified = "2022-10-05"
		reference = "https://github.com/avast/ioc"
		source_url = "https://github.com/avast/ioc/blob/b515ef8c40e107f0cb519789bc1c5be5bdcb9d6b/Manjusaka/Manjusaka.yar#L95-L122"
		license_url = "N/A"
		hash = "0063e5007566e0a7e8bfd73c4628c6d140b332df4f9afbb0adcf0c832dd54c2b"
		hash = "76eb9af0e2f620016d63d38ddb86f0f3f8f598b54146ad14e6af3d8f347dd365"
		hash = "0a5174b5181fcd6827d9c4a83e9f0423838cbb5a6b23d012c3ae414b31c8b0da"
		hash = "63e7f6fa89faa88b346d0cceddf2ef2e3ebf5d5828aa0087663c227422041db7"
		hash = "400855b63b8452221869630c58b7ab03373dabf77c0f10df635e746c13f98ea9"
		hash = "4eb337c12f0e0ee73b3209bed4b819719c4af9f63f3e81dbc3bbf06212450f1c"
		logic_hash = "bbc496788381b57b3ea2814dd61a824d552233f9c5f73287f8bc284252fbedfe"
		score = 75
		quality = 90
		tags = ""

	strings:
		$s01 = "proc/meminfo/proc/uptime/etc/os-releaseVERSION_ID=NAME=DISTRIB_ID"
		$s02 = "/root/.cargo/registry/src/mirrors.ustc.edu.cn"
		$s03 = "cmdlineexecwdassertion failed"
		$s04 = "/etc/passwd/root/"
		$s11 = "./protos/cs.rstargetpidAgentsagentAgentUpdatesleepenckeysysinfoConfigPluginExecPluginLoadReqCwd"
		$s12 = "ReqScreenH"
		$s13 = "manjusakahttp:"
		$s14 = "pluginexecpluginloadreqcwdreqcmd"
		$s15 = "/NPSC2/npc/libs/"

	condition:
		AVASTTI_ELF_PRIVATE and ( all of ($s0*) and any of ($s1*))
}