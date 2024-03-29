rule MALPEDIA_Win_Dridex_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "fd4d4346-8d83-5613-888d-88569f1753b9"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dridex"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.dridex_auto.yar#L1-L1066"
		license_url = "N/A"
		logic_hash = "7f3078493ad3e901d3230994f499bb2b8f95c8666fe5cee6d8f3649c308a4e21"
		score = 75
		quality = 50
		tags = "FILE"
		version = "1"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"

	strings:
		$sequence_0 = { ffd6 85c0 7512 e8???????? eb03 }
		$sequence_1 = { e8???????? b910270000 e8???????? e8???????? }
		$sequence_2 = { c605????????01 c3 c605????????00 c3 }
		$sequence_3 = { 83f8ff 7505 e8???????? 3d34270000 }
		$sequence_4 = { ffd0 85c0 751f e8???????? }
		$sequence_5 = { ffd0 e8???????? 85c0 74de }
		$sequence_6 = { 53 53 53 6a01 53 ffd0 }
		$sequence_7 = { eb0a e8???????? eb03 6a7f 58 }
		$sequence_8 = { c3 31c0 c3 50 }
		$sequence_9 = { 7406 42 803a00 75fa }
		$sequence_10 = { 7403 56 ffd0 33f6 }
		$sequence_11 = { e8???????? 85c0 7407 56 ffd0 }
		$sequence_12 = { 807c241400 7409 8d4c2410 e8???????? }
		$sequence_13 = { e8???????? 6880000000 53 53 }
		$sequence_14 = { e8???????? 85c0 7408 6a00 ffd0 }
		$sequence_15 = { e8???????? 6a00 8d4e1c e8???????? }
		$sequence_16 = { e8???????? eb0a b9d0070000 e8???????? }
		$sequence_17 = { ffd0 5b c3 33c0 }
		$sequence_18 = { c70350000000 eb0d 3da665f63e 7506 }
		$sequence_19 = { e8???????? 85c0 7404 6a7f }
		$sequence_20 = { 85c0 7407 685a040000 ffd0 }
		$sequence_21 = { e8???????? 3db20d7897 7508 c70350000000 }
		$sequence_22 = { 8bc8 e8???????? 6a70 8bc8 e8???????? 6a73 8bc8 }
		$sequence_23 = { 50 e8???????? 8938 8b35???????? }
		$sequence_24 = { 6a00 6a00 8d4dfc 51 6aff }
		$sequence_25 = { e8???????? 6a74 8bc8 e8???????? 6a74 8bc8 }
		$sequence_26 = { 6810270000 50 e8???????? 83c410 }
		$sequence_27 = { 7411 c7461003000000 e8???????? 894614 }
		$sequence_28 = { 85c0 7415 6a01 6a00 6a00 }
		$sequence_29 = { 6a00 8bcf e8???????? 50 ffd6 }
		$sequence_30 = { eb08 83ca20 eb03 83ca10 }
		$sequence_31 = { 46 e8???????? c1e802 3bf0 }
		$sequence_32 = { e8???????? e9???????? 807c245000 740a }
		$sequence_33 = { e8???????? 8d4dc4 e8???????? 5e }
		$sequence_34 = { 6802100000 68ffff0000 ff36 ffd0 }
		$sequence_35 = { ffd0 85c0 7510 e8???????? }
		$sequence_36 = { c20400 55 8bec 83ec34 8365fc00 }
		$sequence_37 = { 89442404 eb00 8b442404 89c1 89ca }
		$sequence_38 = { 7414 31c0 89c1 8b442424 88c2 8854240f }
		$sequence_39 = { 8b442428 6689c1 66894c2458 66894c245a }
		$sequence_40 = { 8a442427 a801 7534 eb00 31c0 89c1 }
		$sequence_41 = { 6a64 59 e8???????? 33c9 e8???????? }
		$sequence_42 = { 51 6801100000 68ffff0000 ff36 }
		$sequence_43 = { 7406 6a02 ff36 ffd0 }
		$sequence_44 = { 740d 40 83c104 3d00100000 }
		$sequence_45 = { 885c2407 89442408 7598 8a442407 a801 }
		$sequence_46 = { c7461002000000 eb0f c7461003000000 e8???????? }
		$sequence_47 = { 890424 894c2404 75dd 8b0424 }
		$sequence_48 = { e8???????? 50 56 8bcb e8???????? 50 e8???????? }
		$sequence_49 = { 8954242c 8b44242c 89c1 89ca }
		$sequence_50 = { eb0a b988130000 e8???????? 33d2 }
		$sequence_51 = { 740a 488d4c2448 e8???????? 488d4c2430 e8???????? e9???????? }
		$sequence_52 = { e8???????? 84c0 740f 6a05 }
		$sequence_53 = { e8???????? 8be8 85ed 7458 }
		$sequence_54 = { e8???????? 6880000000 55 55 }
		$sequence_55 = { ff7508 ffd0 33c0 40 5d }
		$sequence_56 = { c3 55 8bec 837d0800 7422 }
		$sequence_57 = { 8d4de0 51 68???????? ffd0 }
		$sequence_58 = { 6a73 e8???????? 833f00 7523 }
		$sequence_59 = { 6a00 6a02 ffd0 50 }
		$sequence_60 = { e8???????? 8bc8 a1???????? ff30 }
		$sequence_61 = { 5e c3 31c0 89c2 }
		$sequence_62 = { e8???????? 50 ffd7 85c0 7512 }
		$sequence_63 = { eb0c e8???????? 8bf0 eb03 6a7f 5e }
		$sequence_64 = { 8b45cc 31c9 8b55d0 39c2 }
		$sequence_65 = { 8038e9 89c1 8945d0 894dcc }
		$sequence_66 = { e8???????? 50 53 8d4dd0 e8???????? 50 }
		$sequence_67 = { 8b45e8 05ffff0000 25ffff0000 83c001 }
		$sequence_68 = { 8b4de8 81c1ffff0000 81e1ffff0000 83c101 }
		$sequence_69 = { 50 8b442408 8038e9 890424 7517 8b0424 8b4801 }
		$sequence_70 = { 8b704c 2b7134 891424 89742404 894c2418 e8???????? }
		$sequence_71 = { 8b55bc 8955c4 776a 31c0 8b4dac 8b510c }
		$sequence_72 = { 807c0805e9 891424 74e9 8b0424 }
		$sequence_73 = { 8b450c 8b4d08 8b503c 6689d6 6683fe00 89c7 8945f0 }
		$sequence_74 = { 83c001 8b4de8 01c1 894de0 }
		$sequence_75 = { 7517 8b0424 8b4801 89c2 01ca 83c205 }
		$sequence_76 = { 8b513c 6689d6 6683fe00 89cf 8945f0 894dec }
		$sequence_77 = { 01ca 83c205 807c0805e9 891424 }
		$sequence_78 = { 89c7 8945f0 894dec 8955e8 897de4 }
		$sequence_79 = { 5b 5e 5d c3 55 89e5 6a00 }
		$sequence_80 = { 83c001 8b4df8 01c1 894df0 8b45f0 }
		$sequence_81 = { 83c454 5b 5e 5f 5d c3 55 }
		$sequence_82 = { 894df0 8b45f0 83c40c 5e }
		$sequence_83 = { e9???????? 8b45e0 83c438 5f }
		$sequence_84 = { 8945f8 894df4 8975f0 7418 8b45f4 05ffff0000 }
		$sequence_85 = { 25ffff0000 83c001 8b4da8 01c1 }
		$sequence_86 = { 8945c4 894dc0 885dbf 8975b8 }
		$sequence_87 = { c3 55 89e5 57 56 53 83ec54 }
		$sequence_88 = { 5b 5d c3 8b45d0 8b4dd4 668b55d8 31f6 }
		$sequence_89 = { 8b45e0 83c45c 5f 5b 5e 5d }
		$sequence_90 = { 53 56 83ec38 8b450c 8b4d08 }
		$sequence_91 = { c7424800b00400 8b7c2418 c787cc00000000000000 c787c800000000000000 }
		$sequence_92 = { 8955cc 74bc 8b45cc 83c454 5b 5e }
		$sequence_93 = { 6a00 e8???????? 83c408 c3 6a00 68???????? }
		$sequence_94 = { 8d442448 b91c000000 8b542438 891424 89442404 c74424081c000000 894c2434 }
		$sequence_95 = { 893c24 89442404 c744240804000000 8954240c 89ac248c000000 898c2488000000 }
		$sequence_96 = { 8945c8 75e4 83c448 5e 5f 5b 5d }
		$sequence_97 = { 53 83ec74 8b450c 8b4d08 31d2 8b713c }
		$sequence_98 = { 0f85dafeffff 8b45e4 83c474 5b }
		$sequence_99 = { 55 89e5 56 57 53 83ec70 }
		$sequence_100 = { 53 81ecb0000000 8b4508 8d4dd8 c745d800000000 }
		$sequence_101 = { 5b 5d c3 8b45f0 8b0c8504406e00 8b55f8 39d1 }
		$sequence_102 = { 8b0c8504406e00 8b55f8 39d1 8945ec 894de8 7212 }
		$sequence_103 = { 83f900 89442464 0f84f2010000 b801000000 8b4c2468 8b91a4000000 }
		$sequence_104 = { 83c470 5b 5f 5e 5d c3 }
		$sequence_105 = { 8b45e0 83c438 5e 5b }
		$sequence_106 = { 57 83ec20 8b4508 890424 }
		$sequence_107 = { 890424 e8???????? 31c0 83c420 5f }
		$sequence_108 = { c7424800c00400 8b7de4 c787cc00000000000000 c787c800000000000000 }
		$sequence_109 = { 897dd8 8b45d8 83c444 5b 5e 5f }
		$sequence_110 = { e8???????? 8d0d44306e00 31d2 8b75f8 89462c }
		$sequence_111 = { 894620 890c24 c744240400000000 8955e0 e8???????? 8d0dd8306e00 890424 }
		$sequence_112 = { 8d155e306e00 83ec04 891424 8945e8 894de4 }
		$sequence_113 = { 8b55f4 8b75ec 89723c c7424004000000 c742442c0c0200 c7424800b00400 }
		$sequence_114 = { 55 89e5 53 56 57 83ec38 8b450c }
		$sequence_115 = { c742442c0c0200 c7424800b00400 8b7de4 c787cc00000000000000 }
		$sequence_116 = { 8d0dbc306e00 890424 894c2404 e8???????? 8d0d44306e00 }
		$sequence_117 = { 74bc 8b45cc 83c454 5f 5b 5e }
		$sequence_118 = { 0f84e2feffff e9???????? 8b45e0 83c45c 5e 5f 5b }
		$sequence_119 = { 56 53 57 83ec44 8b4508 }
		$sequence_120 = { 8955e0 e8???????? 8d0dd8302700 890424 }
		$sequence_121 = { 89462c 890c24 c744240400000000 8955d8 e8???????? 8d0d04318400 }
		$sequence_122 = { c7424004000000 c7424499040200 c7424800c00400 8b7de4 }
		$sequence_123 = { c3 55 89e5 83ec10 8b4508 8d0d44302500 }
		$sequence_124 = { 56 83ec44 8b4508 8d0d30302500 31d2 890c24 }
		$sequence_125 = { 31c0 8d0d5a232f00 8b55c8 39ca 8945cc 0f84f9000000 }
		$sequence_126 = { 890c24 c744240400000000 8955e4 e8???????? 8d0dc9302f00 890424 894c2404 }
		$sequence_127 = { 8d0d44302f00 31d2 8b75f8 894608 890c24 c744240400000000 }
		$sequence_128 = { 8d0d30302700 31d2 890c24 c744240400000000 8945f0 8955ec e8???????? }

	condition:
		7 of them and filesize <1040384
}
