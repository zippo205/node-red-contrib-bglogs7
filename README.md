BGlogS7 Node-RED node
===

[![GitHub release](https://img.shields.io/github/release/dbaba/node-red-contrib-device-stats.svg)](https://github.com/zippo205/node-red-contrib-bglogs7/releases/latest)
[![master Build Status](https://travis-ci.org/dbaba/node-red-contrib-device-stats.svg?branch=master)](https://travis-ci.org/zippo205/node-red-contrib-bglogs7/)
[![License MIT](https://img.shields.io/github/license/dbaba/node-red-contrib-device-stats.svg)](http://opensource.org/licenses/MIT)

**Note that this is a very special kind of logging interface. It is not a Siemens standard and is only supported by a certain plant manufacturer from Germany.**

This node creates socket connection to a Siemens PLC according to the node settings on the editor. The received logs will be embedded into msg.payload and emitted to the output port.


### Installation

```
cd ~/.node-red
npm install node-red-contrib-bglogs7
```

# Revision History

* 1.0.1
  - Fix deployment error

* 1.0.0
  - Initial public release

# Copyright and License

The project is released under MIT License. See LICENSE for detail.