## ruby-pcap

[![Build Status](https://travis-ci.org/codeout/ruby-pcap.svg?branch=ruby-pcap-gem)](https://travis-ci.org/codeout/ruby-pcap)

ruby-pcap は Ruby から LBL の libpcap (Packet Capture library) へアク
セスするための拡張ライブラリです。TCP/IPのヘッダの情報にアクセスするた
めのクラスも含んでいます。

## インストール

```
gem install ruby-pcap
```

### 必要なもの

* ruby-1.9.3以上
  * 古いバージョンでも動くかもしれませんが、テストされていません
* libpcap (http://www.tcpdump.org/)

## 使い方

doc および doc-ja ディレクトリ以下にあるファイルを見て下さい。
examples ディレクトリに簡単なサンプルスクリプトがあります。

## 作者

福嶋正機 <fukusima@goto.info.waseda.ac.jp>

## メンテナー

Marcus Barczak <mbarczak@etsy.com>

## 著作権表示

ruby-pcapは福嶋正機が著作権を保持する free software です。

ruby-pcapはGPL(GNU GENERAL PUBLIC LICENSE)に従って再配布または
変更することができます。GPLについてはCOPYINGファイルを参照して
ください。

ruby-pcapは無保証です。作者はruby-pcapのバグなどから発生する
いかなる損害に対しても責任を持ちません。詳細については GPL を
参照してください。
