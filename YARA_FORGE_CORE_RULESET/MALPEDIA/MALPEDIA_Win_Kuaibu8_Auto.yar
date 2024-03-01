rule MALPEDIA_Win_Kuaibu8_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "91f1248d-ab2b-5079-b9e0-a51e87297924"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kuaibu8"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.kuaibu8_auto.yar#L1-L127"
		license_url = "N/A"
		logic_hash = "cbf2ea9a6bca6a983b840d14cd3e4818a640e713858e86101c3fa57dacf19221"
		score = 75
		quality = 75
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
		$sequence_0 = { 53 e8???????? 83c404 58 8945e4 8b5ddc }
		$sequence_1 = { 895dc8 6a00 6a00 6a00 6804000080 }
		$sequence_2 = { 52 e8???????? 83c404 8d0c2f 8bf0 8b03 }
		$sequence_3 = { e9???????? 8b5dec e8???????? 8945d8 837dd803 0f8586010000 }
		$sequence_4 = { ff75f4 e8???????? 83c408 83f800 0f8521000000 8b45fc 85c0 }
		$sequence_5 = { 81ec30000000 c745fc00000000 8965f8 8b5d08 ff33 ff15???????? 90 }
		$sequence_6 = { e8???????? 8945d4 8b5ddc 85db 7409 }
		$sequence_7 = { 53 e8???????? 83c404 58 8945f4 6805000000 e8???????? }
		$sequence_8 = { dd5de8 dd45e8 dc25???????? dd5de0 8b5df8 e8???????? b802000000 }
		$sequence_9 = { 83c404 8803 e9???????? bd02000000 55 e8???????? 668b4e0c }

	condition:
		7 of them and filesize <737280
}
