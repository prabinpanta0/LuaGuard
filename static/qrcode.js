/**
 * @fileoverview
 * Simple QR Code generator for TOTP
 * Simplified for MFA setup page
 */
var QRCode = function() {
  
  // QR Code Pattern
  var PAD0 = 0xEC;
  var PAD1 = 0x11;
  
  var _typeNumber = 4;
  var _errorCorrectionLevel = 'L';
  var _dataCache = null;
  var _dataList = [];
  
  var _this = {};
  
  var makeImpl = function(text) {
    var qrCode = QRCodeModel(_typeNumber, _errorCorrectionLevel);
    qrCode.addData(text);
    qrCode.make();
    return qrCode;
  };
  
  _this.toDataURL = function(text, options, cb) {
    if (typeof options === 'function') {
      cb = options;
      options = {};
    }
    
    options = options || {};
    var size = options.width || 256;
    var margin = (typeof options.margin === 'undefined') ? 4 : options.margin;
    
    var qr = makeImpl(text);
    var canvas = document.createElement('canvas');
    var ctx = canvas.getContext('2d');
    var cellSize = size / (qr.getModuleCount() + 2 * margin);
    var actualSize = qr.getModuleCount() * cellSize;
    var topLeftMargin = (size - actualSize) / 2;
    
    canvas.width = canvas.height = size;
    ctx.fillStyle = '#fff';
    ctx.fillRect(0, 0, size, size);
    ctx.fillStyle = '#000';
    
    for (var row = 0; row < qr.getModuleCount(); row++) {
      for (var col = 0; col < qr.getModuleCount(); col++) {
        if (qr.isDark(row, col)) {
          ctx.fillRect(
            Math.round(topLeftMargin + col * cellSize),
            Math.round(topLeftMargin + row * cellSize),
            Math.ceil(cellSize),
            Math.ceil(cellSize)
          );
        }
      }
    }
    
    cb(null, canvas.toDataURL());
  };
  
  // QRCode Model implementation
  function QRCodeModel(typeNumber, errorCorrectionLevel) {
    // Basic Module creation logic
    var PAD0 = 0xEC;
    var PAD1 = 0x11;
    var _moduleCount = 0;
    var _modules = null;
    var _dataCache = null;
    var _dataList = [];
    
    var _this = {};
    
    _this.isDark = function(row, col) {
      if (row < 0 || _moduleCount <= row || col < 0 || _moduleCount <= col) {
        throw new Error(row + "," + col);
      }
      return _modules[row][col];
    };
    
    _this.getModuleCount = function() {
      return _moduleCount;
    };
    
    _this.make = function() {
      _moduleCount = typeNumber * 4 + 17;
      _modules = new Array(_moduleCount);
      for (var i = 0; i < _moduleCount; i++) {
        _modules[i] = new Array(_moduleCount);
        for (var j = 0; j < _moduleCount; j++) {
          _modules[i][j] = null;
        }
      }
      setupPositionProbePattern(0, 0);
      setupPositionProbePattern(_moduleCount - 7, 0);
      setupPositionProbePattern(0, _moduleCount - 7);
      setupPositionAdjustPattern();
      setupTimingPattern();
      setupFormatInfo();
      if (typeNumber >= 7) {
        setupVersionInfo();
      }
      mapData(createData());
    };
    
    _this.addData = function(data) {
      var newData = new QR8bitByte(data);
      _dataList.push(newData);
      _dataCache = null;
    };
    
    var setupPositionProbePattern = function(row, col) {
      for (var r = -1; r <= 7; r++) {
        if (row + r <= -1 || _moduleCount <= row + r) continue;
        for (var c = -1; c <= 7; c++) {
          if (col + c <= -1 || _moduleCount <= col + c) continue;
          if ((0 <= r && r <= 6 && (c == 0 || c == 6))
            || (0 <= c && c <= 6 && (r == 0 || r == 6))
            || (2 <= r && r <= 4 && 2 <= c && c <= 4)) {
            _modules[row + r][col + c] = true;
          } else {
            _modules[row + r][col + c] = false;
          }
        }
      }
    };
    
    var setupPositionAdjustPattern = function() {
      // Corrected coordinates for Type 4 QR code
      var pos = [6, 28];
      for (var i = 0; i < pos.length; i++) {
        for (var j = 0; j < pos.length; j++) {
          var row = pos[i];
          var col = pos[j];
          if (_modules[row][col] != null) continue;
          for (var r = -2; r <= 2; r++) {
            for (var c = -2; c <= 2; c++) {
              if (r == -2 || r == 2 || c == -2 || c == 2 || (r == 0 && c == 0)) {
                _modules[row + r][col + c] = true;
              } else {
                _modules[row + r][col + c] = false;
              }
            }
          }
        }
      }
    };
    
    var setupTimingPattern = function() {
      for (var r = 8; r < _moduleCount - 8; r++) {
        if (_modules[r][6] != null) continue;
        _modules[r][6] = (r % 2 == 0);
      }
      for (var c = 8; c < _moduleCount - 8; c++) {
        if (_modules[6][c] != null) continue;
        _modules[6][c] = (c % 2 == 0);
      }
    };
    
    var setupFormatInfo = function() {
      for (var i = 0; i < 8; i++) {
        _modules[i][8] = false;
        _modules[8][i] = false;
      }
      _modules[8][8] = false;
      for (var i = _moduleCount - 8; i < _moduleCount; i++) {
        _modules[i][8] = false;
        _modules[8][i] = false;
      }
    };
    
    var setupVersionInfo = function() {
      for (var i = 0; i < 6; i++) {
        for (var j = 0; j < 3; j++) {
          _modules[i][_moduleCount - 11 + j] = false;
          _modules[_moduleCount - 11 + j][i] = false;
        }
      }
    };
    
    var createData = function() {
      var buffer = new QRBitBuffer();
      for (var i = 0; i < _dataList.length; i++) {
        var data = _dataList[i];
        buffer.put(data.getMode(), 4);
        buffer.put(data.getLength(), 8);
        data.write(buffer);
      }
      return buffer;
    };
    
    var mapData = function(data) {
      var inc = -1;
      var row = _moduleCount - 1;
      var bitIndex = 7;
      var byteIndex = 0;
      for (var col = _moduleCount - 1; col > 0; col -= 2) {
        if (col == 6) col--;
        while (true) {
          for (var c = 0; c < 2; c++) {
            if (_modules[row][col - c] == null) {
              var dark = false;
              if (byteIndex < data.length) {
                dark = ((data[byteIndex] >>> bitIndex) & 1) == 1;
              }
              if (dark) {
                _modules[row][col - c] = dark;
              } else {
                _modules[row][col - c] = false;
              }
              bitIndex--;
              if (bitIndex == -1) {
                byteIndex++;
                bitIndex = 7;
              }
            }
          }
          row += inc;
          if (row < 0 || _moduleCount <= row) {
            row -= inc;
            inc = -inc;
            break;
          }
        }
      }
    };
    
    return _this;
  }
  
  // QR8bitByte
  function QR8bitByte(data) {
    var _data = data;
    var _bytes = [];
    
    var _this = {};
    
    _this.getMode = function() { return 4; };
    
    _this.getLength = function() { return _bytes.length; };
    
    _this.write = function(buffer) {
      for (var i = 0; i < _bytes.length; i++) {
        buffer.put(_bytes[i], 8);
      }
    };
    
    // Initialize
    for (var i = 0; i < _data.length; i++) {
      var code = _data.charCodeAt(i);
      _bytes.push(code);
    }
    
    return _this;
  }
  
  // QRBitBuffer
  function QRBitBuffer() {
    var _buffer = [];
    var _length = 0;
    
    var _this = {};
    
    _this.getBuffer = function() { return _buffer; };
    
    _this.getLengthInBits = function() { return _length; };
    
    _this.get = function(index) {
      var bufIndex = Math.floor(index / 8);
      return ((_buffer[bufIndex] >>> (7 - index % 8)) & 1) == 1;
    };
    
    _this.put = function(num, length) {
      for (var i = 0; i < length; i++) {
        _this.putBit(((num >>> (length - i - 1)) & 1) == 1);
      }
    };
    
    _this.putBit = function(bit) {
      var bufIndex = Math.floor(_length / 8);
      if (_buffer.length <= bufIndex) {
        _buffer.push(0);
      }
      if (bit) {
        _buffer[bufIndex] |= (0x80 >>> (_length % 8));
      }
      _length++;
    };
    
    return _this;
  }
  
  return _this;
}();