rule MALPEDIA_Win_Isfb_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "2206addc-4ea1-5ebc-8989-ba5f49383e7b"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.isfb"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.isfb_auto.yar#L1-L1623"
		license_url = "N/A"
		logic_hash = "dcaa8c2fe85dec9e7e215d7d6083b8c053dc5e8814c7849f4addcdf0f2d4a23f"
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
		$sequence_0 = { e8???????? eb02 33c0 3bc7 741b 50 }
		$sequence_1 = { 741b 50 33c0 e8???????? 3bc7 }
		$sequence_2 = { ff75f0 ff75f4 6822010000 e9???????? ff7508 }
		$sequence_3 = { 58 e8???????? 3bc7 7406 50 }
		$sequence_4 = { 3bc7 7413 50 6a10 58 e8???????? }
		$sequence_5 = { ff35???????? e8???????? 8bf0 3bf3 7443 6aff 68806967ff }
		$sequence_6 = { 50 e8???????? 83c40c e8???????? 3bc7 }
		$sequence_7 = { 6a64 ff15???????? a1???????? 85c0 7407 83ee64 }
		$sequence_8 = { ff35???????? ff15???????? 85c0 a3???????? 7402 ffe0 c20400 }
		$sequence_9 = { 5d 5b 59 c20400 8325????????00 6a00 68???????? }
		$sequence_10 = { 7406 50 e8???????? 3bdf 7414 }
		$sequence_11 = { a1???????? 85c0 751a 68???????? ff35???????? ff15???????? 85c0 }
		$sequence_12 = { 3c05 7506 84e4 7704 3ac0 }
		$sequence_13 = { c20400 55 8bec 83ec0c a1???????? 8365f800 }
		$sequence_14 = { 2b55fc 8b7d10 0155fc 83451004 }
		$sequence_15 = { 83e103 740d 51 50 ff7510 e8???????? 83c40c }
		$sequence_16 = { 0155fc 83451004 83c004 49 8917 75e9 }
		$sequence_17 = { 7417 8b10 2b55fc 8b7d10 }
		$sequence_18 = { 3bc3 7512 e8???????? 3bc3 a3???????? }
		$sequence_19 = { 895df4 0f84c7000000 56 53 }
		$sequence_20 = { b8???????? 7505 b8???????? 53 bb60ea0000 }
		$sequence_21 = { 68000f0000 e8???????? 8bd8 85db 895df4 0f84c7000000 }
		$sequence_22 = { 837b240c 56 57 8b3b 897c241c 760a 8b4b20 }
		$sequence_23 = { 894b34 8b4b24 2b4b28 894c2410 8b4b34 f6c140 }
		$sequence_24 = { 58 e8???????? 85c0 740d 8906 83c604 }
		$sequence_25 = { 8b442418 894110 836334f9 c7432c01000000 8b4334 }
		$sequence_26 = { e8???????? 8b4320 897324 897328 83c40c 8974240c c6401a00 }
		$sequence_27 = { 57 33ff 3bdf 7414 }
		$sequence_28 = { ff35???????? 0fc8 50 a1???????? }
		$sequence_29 = { 8a4604 2404 f6d8 1bc0 }
		$sequence_30 = { c6400731 8b74241c 8b1e 6a00 ff37 ff15???????? 2b442414 }
		$sequence_31 = { ff15???????? 8b442414 8b4c240c 8907 8b442418 }
		$sequence_32 = { 83ec14 8364240400 53 8b5d0c 837b240c 56 }
		$sequence_33 = { 2b442414 50 8b07 03442418 50 56 ff5310 }
		$sequence_34 = { 837d0800 7408 ff7508 e8???????? 8bc7 5f 5e }
		$sequence_35 = { 752f 8b450c 8930 eb33 }
		$sequence_36 = { 74a3 33ff eb0b 33ff eb03 }
		$sequence_37 = { 6a01 33db 53 ff35???????? e8???????? 8bf0 }
		$sequence_38 = { 50 8d4508 50 53 8bc6 }
		$sequence_39 = { 8bd1 83c128 4e 7404 3bd0 74e7 3bd0 }
		$sequence_40 = { 488bcf c744242860ea0000 4c0f45c8 48895c2420 }
		$sequence_41 = { 3bc8 7415 8b5210 3bd0 }
		$sequence_42 = { 53 8bc6 e8???????? 85c0 7516 }
		$sequence_43 = { 6a0b eb02 6a02 58 }
		$sequence_44 = { 85ff 750e 837d0800 7408 }
		$sequence_45 = { 488bcf ff15???????? 4c8964dd00 83c301 4885ff 4c8be7 }
		$sequence_46 = { 498bcc ff15???????? 33db 66ba2000 }
		$sequence_47 = { 415c 5f 5e 5d 5b c3 8b4754 }
		$sequence_48 = { 75c4 48892e eb02 33db 488b0d???????? 885e08 }
		$sequence_49 = { c21000 55 8bec 83ec14 a1???????? 53 }
		$sequence_50 = { 53 b800080000 50 56 ff35???????? }
		$sequence_51 = { e8???????? be01000000 8bc6 4883c440 415e }
		$sequence_52 = { 33db 66ba2000 498bcc ff15???????? 4885c0 }
		$sequence_53 = { e8???????? 85c0 742d ff75fc 6a0d }
		$sequence_54 = { 742d ff75fc 6a0d 58 e8???????? 85c0 }
		$sequence_55 = { ff15???????? 4885c0 488be8 7453 }
		$sequence_56 = { 4c0f45c8 48895c2420 e8???????? 85c0 8bd8 }
		$sequence_57 = { 51 50 57 6a01 ff75e0 68???????? e8???????? }
		$sequence_58 = { ff15???????? bb01000000 498bcc eb07 83c301 488d4801 66ba2000 }
		$sequence_59 = { 8bd5 488bcf bb57000000 e8???????? }
		$sequence_60 = { e8???????? 3bc3 740f 8b35???????? 50 83c604 }
		$sequence_61 = { a810 ff750c 7535 68???????? ff75f8 }
		$sequence_62 = { ff75f8 ffd6 8b4df4 66c7015c00 }
		$sequence_63 = { 8945e0 e8???????? 85c0 0f84dc000000 8b45e0 8d4de0 3bc1 }
		$sequence_64 = { 33db 53 ff35???????? c745f408000000 ff15???????? 3bc3 8945f8 }
		$sequence_65 = { 6641b85c00 33d2 488bcd ff15???????? }
		$sequence_66 = { 50 83c604 e8???????? 3bfb }
		$sequence_67 = { b90e010000 41b800000100 4889442420 e8???????? e9???????? }
		$sequence_68 = { 6a01 e8???????? 85db 7423 8b0d???????? }
		$sequence_69 = { 50 e8???????? 3bfb 7414 }
		$sequence_70 = { 72c1 eb0c bb7f000000 eb05 bb7e000000 }
		$sequence_71 = { 33d2 ff15???????? 488bdf 8bf7 483bdf }
		$sequence_72 = { 4883c608 83fd05 72c1 eb0c }
		$sequence_73 = { 3bc3 8945f4 741a ff750c 668918 68???????? }
		$sequence_74 = { 50 8bd7 e8???????? eb02 33c0 3bc3 7413 }
		$sequence_75 = { a840 0f84e2000000 8b7334 8d442418 50 8d442410 50 }
		$sequence_76 = { 8b7508 e8???????? 33f6 3975fc }
		$sequence_77 = { ff7510 57 ff750c 53 e8???????? 3bfe 740e }
		$sequence_78 = { 0f8544010000 8b472c a801 742d ff37 e8???????? 85c0 }
		$sequence_79 = { e8???????? 3bfe 740e 57 56 ff35???????? ff15???????? }
		$sequence_80 = { ff5214 8bf7 8bfe e8???????? 5f 5e }
		$sequence_81 = { 5b 8be5 5d c20800 8b4330 a804 0f8451ffffff }
		$sequence_82 = { c744242000010000 ff15???????? 4883f8ff 488bf8 7442 }
		$sequence_83 = { ff15???????? 53 56 ff35???????? ff15???????? 5b 5f }
		$sequence_84 = { 3975fc 7410 ff75fc 56 ff35???????? ff15???????? 53 }
		$sequence_85 = { 83bc248800000000 4c8b442440 488b542448 894c2430 }
		$sequence_86 = { 752e 53 e8???????? 6a01 6a01 }
		$sequence_87 = { 56 ff35???????? 8945f8 ff15???????? 8bd8 3bde }
		$sequence_88 = { e8???????? 85c0 0f85d7000000 8b4604 }
		$sequence_89 = { 7505 894720 eb0b 8b4f30 84c9 0f8992000000 }
		$sequence_90 = { 83632800 e9???????? 8b4330 a840 0f84e2000000 8b7334 }
		$sequence_91 = { 0f854affffff 894330 e9???????? 55 }
		$sequence_92 = { c9 c20400 51 56 ff74240c }
		$sequence_93 = { 4803df 410fb64101 33d2 488d0cc3 }
		$sequence_94 = { 85d2 4d8bf1 458bf8 8bc2 }
		$sequence_95 = { e8???????? 8d45fc 50 8b4508 e8???????? }
		$sequence_96 = { 50 57 e8???????? e9???????? 68???????? }
		$sequence_97 = { ff15???????? 488bcf 48870d???????? 483bcf }
		$sequence_98 = { 33db 895d08 eb03 8b5d08 }
		$sequence_99 = { 488d0cc3 48890d???????? 410fb64103 488d0cc3 }
		$sequence_100 = { ff15???????? 4885db 740c 4c8b0d???????? e9???????? }
		$sequence_101 = { c3 418bd8 4803df 410fb64101 }
		$sequence_102 = { e8???????? 85c0 7507 33db 895d08 }
		$sequence_103 = { 488bce ff15???????? 488b0d???????? 33d2 4c63c0 }
		$sequence_104 = { 6a00 ff35???????? ff15???????? 33db 6a01 }
		$sequence_105 = { 8a4b1c 488b4558 4c8b4d30 4c8b4510 }
		$sequence_106 = { 448be8 418b4310 41394308 410f474308 }
		$sequence_107 = { 488d0cc3 48890d???????? 410fb64102 488d0cc3 }
		$sequence_108 = { 33d2 ff15???????? 483bc3 4c8be8 }
		$sequence_109 = { 33d2 498bcc 498bfd e8???????? 493bc5 7405 }
		$sequence_110 = { 5b c3 a1???????? 83c040 50 ff15???????? eb08 }
		$sequence_111 = { 8b3d???????? 56 ffd7 53 56 }
		$sequence_112 = { e8???????? 0945fc 47 83c304 3b3e 72dc 8b45fc }
		$sequence_113 = { c9 c20400 53 56 8bf0 8a06 }
		$sequence_114 = { 8bf1 05fefeffff 33db 33c9 }
		$sequence_115 = { 8b02 43 8acb d3c0 33c6 33442410 8bf0 }
		$sequence_116 = { ff15???????? 8ac3 5b c9 c20400 53 }
		$sequence_117 = { 8bf0 8932 83c204 ff4c240c 75e6 5e 5b }
		$sequence_118 = { 4533c9 4889442428 215c2420 4533c0 }
		$sequence_119 = { 50 8d442430 50 8d442428 50 8d442428 }
		$sequence_120 = { 480f45f2 832700 458be0 bb08000000 }
		$sequence_121 = { ff15???????? 4c8d4c2450 4c8d442458 8d5001 488bce e8???????? 85c0 }
		$sequence_122 = { ff15???????? 4883f8ff 4c8be0 0f8583000000 488b0d???????? 4d8bc5 }
		$sequence_123 = { e9???????? 33c9 bb26040000 48870d???????? }
		$sequence_124 = { ff15???????? 49bb00c0692ac9000000 488bcf 4c019c24d8010000 ff15???????? 6641b85c00 33d2 }
		$sequence_125 = { 83c701 e9???????? 488b8424c8010000 498bcc bb01000000 4c8928 }
		$sequence_126 = { ff15???????? 488d542440 488bcd ff15???????? 4883f8ff }
		$sequence_127 = { 4c8bc7 33d2 ff15???????? 33ff 4885ff }
		$sequence_128 = { 488bd6 ff15???????? eb14 488b0d???????? 4c8bc7 33d2 }
		$sequence_129 = { 6a00 ff35???????? ffd3 8bd8 85db 7476 }
		$sequence_130 = { 41b905000000 488bd8 ff15???????? 488bcb }
		$sequence_131 = { 4c8be8 0f841c010000 448b05???????? 33d2 488bc8 4c33c7 e8???????? }
		$sequence_132 = { 7416 a1???????? 83c004 50 be???????? }
		$sequence_133 = { 498bcf ff15???????? 448bf0 488bce ff15???????? }
		$sequence_134 = { 895df4 895df0 c745f857000000 bf19010000 }
		$sequence_135 = { 7520 41390424 741a 498d4c2401 }
		$sequence_136 = { 488b0d???????? 448bc0 8bd8 33d2 4983c001 }
		$sequence_137 = { a1???????? 25efff0000 0bc2 e9???????? }
		$sequence_138 = { 4c63c0 33d2 4983c00c ff15???????? }
		$sequence_139 = { 215c2420 4533c9 4533c0 33d2 ff15???????? 85c0 7511 }
		$sequence_140 = { 6a03 8935???????? 8935???????? 8935???????? }
		$sequence_141 = { e9???????? 488bcb ff15???????? a810 }
		$sequence_142 = { 803f2a 750b 4883c701 83c3ff }
		$sequence_143 = { 41be01000000 33c9 418bd6 ff15???????? }
		$sequence_144 = { 53 56 8bf1 05fefeffff }
		$sequence_145 = { 57 4154 4155 4156 4883ec50 488bf1 }
		$sequence_146 = { 5e 33c0 c9 c20400 55 8bec 51 }
		$sequence_147 = { 4889040f 4883c708 492bf6 75db }
		$sequence_148 = { 8bc6 e8???????? 8b06 8b08 57 ff7510 }
		$sequence_149 = { 750a 488bcf e8???????? 8bd8 488b0d???????? 4c8bc7 }
		$sequence_150 = { 5f c20400 55 8bec 83e4f8 81ec9c000000 }
		$sequence_151 = { 488d542438 488bcb e8???????? eb02 }
		$sequence_152 = { 8bc7 e8???????? 8d4618 8b08 50 51 }
		$sequence_153 = { 6a20 40 50 ffd6 }
		$sequence_154 = { 488bd3 ff15???????? 488b8c2428020000 8bf0 ff15???????? }
		$sequence_155 = { 7417 4863461c 2b6e1c 4c03e8 488b4610 48894718 }
		$sequence_156 = { 21442428 488b8c2428020000 488364242000 448d4803 }
		$sequence_157 = { 21b42410020000 eb0d ff15???????? 89842410020000 }
		$sequence_158 = { 488bcb ff15???????? 8bc8 ff15???????? 21b42410020000 }
		$sequence_159 = { 4885c9 7405 e8???????? 4883c428 c3 488d82204a0000 488982284a0000 }
		$sequence_160 = { 418bcd e8???????? 8b842410020000 4c8d9c24f0010000 }
		$sequence_161 = { 488b15???????? 4c8d842428020000 48c7c101000080 ff15???????? }
		$sequence_162 = { e8???????? 5e 5f c9 c3 51 53 }
		$sequence_163 = { 50 57 6a01 ff7508 ffd6 85c0 742b }
		$sequence_164 = { 448bcf 4533c0 e8???????? 483bc3 488905???????? 0f84dc000000 }
		$sequence_165 = { e8???????? 488b0d???????? 4c8bc3 33d2 ff15???????? 488b0d???????? 4c8bc7 }
		$sequence_166 = { 4c8d40cc 33d2 33c9 e8???????? 85c0 0f8561010000 }
		$sequence_167 = { 7415 397b44 7510 488b0b e8???????? 85c0 0f859b000000 }
		$sequence_168 = { ffc1 807c043000 7531 8bd3 2bd1 8917 }
		$sequence_169 = { 84c0 0f89a3000000 8b434c a804 7415 397b44 7510 }
		$sequence_170 = { 7505 217b3c eb0b 8b434c 84c0 0f89a3000000 8b434c }
		$sequence_171 = { 85c0 0f8561010000 8b4348 a801 742c }
		$sequence_172 = { 742c 488b0b e8???????? 85c0 0f85e8000000 488b4608 488b0e }
		$sequence_173 = { 85c0 0f859b000000 4863533c 488b4608 }
		$sequence_174 = { ba10000000 488bc8 e8???????? 48898424e0010000 4885c0 }
		$sequence_175 = { 4c8d442470 488d542440 e8???????? 8bd8 85c0 }
		$sequence_176 = { 33d2 468d44385f ff15???????? 4c8bf0 }
		$sequence_177 = { 488bf8 4885c0 7427 488d542420 b901020000 ff15???????? 85c0 }
		$sequence_178 = { 4c89642448 ff15???????? 8bd8 83f8ff }
		$sequence_179 = { 488bc8 458bf9 33ff e8???????? 4c8be8 4885c0 7508 }
		$sequence_180 = { 8bd8 85c0 0f85f3010000 4c8b842418020000 8d5808 488d8c24b0000000 4d85c0 }
		$sequence_181 = { 448d4256 ff15???????? 4c8be0 4885c0 0f8405010000 ff15???????? }
		$sequence_182 = { 90 57 51 8b742420 8b7c241c 8b4c2434 }
		$sequence_183 = { 56 57 51 90 8b742428 }
		$sequence_184 = { 8b5508 035510 8b3a 83c204 }
		$sequence_185 = { 01f2 6683f9ff 896c2428 7508 }
		$sequence_186 = { eb67 8044241301 0fb6ca 01cb 30c9 eb59 }
		$sequence_187 = { 83c304 894c2410 56 90 }
		$sequence_188 = { 5e 01d5 01d3 b101 3b5c2428 0f8266ffffff }
		$sequence_189 = { 8b5d10 6601da c1ca03 895510 3010 }

	condition:
		7 of them and filesize <2940928
}