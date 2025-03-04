import * as bitcoin from 'bitcoinjs-lib';

// 指定网络（主网）
const NETWORK = bitcoin.networks.bitcoin;

// 扩展的操作码映射（已提供，无需修改）
const OPCODES = {
    0x00: 'OP_0',
    0x51: 'OP_1',
    0x52: 'OP_2',
    0x53: 'OP_3',
    0x54: 'OP_4',
    0x55: 'OP_5',
    0x56: 'OP_6',
    0x57: 'OP_7',
    0x58: 'OP_8',
    0x59: 'OP_9',
    0x5a: 'OP_10',
    0x5b: 'OP_11',
    0x5c: 'OP_12',
    0x5d: 'OP_13',
    0x5e: 'OP_14',
    0x5f: 'OP_15',
    0x60: 'OP_16',
    0x61: 'OP_NOP',
    0x76: 'OP_DUP',
    0x87: 'OP_EQUAL',
    0x88: 'OP_EQUALVERIFY',
    0xa9: 'OP_HASH160',
    0xac: 'OP_CHECKSIG',
    0xad: 'OP_CHECKSIGVERIFY',
    0xae: 'OP_CHECKMULTISIG',
    0xba: 'OP_CHECKSIGADD',
    0x6a: 'OP_RETURN',
    0xb1: 'OP_CHECKLOCKTIMEVERIFY',
    0xb2: 'OP_CHECKSEQUENCEVERIFY',
};

// 脚本类型标识符和说明（已提供，无需修改）
const SCRIPT_TYPES = {
    'P2PKH': '付款到公钥哈希 (Pay-to-Public-Key-Hash)',
    'P2SH': '付款到脚本哈希 (Pay-to-Script-Hash)',
    'P2WPKH': '隔离见证付款到公钥哈希 (Segwit Pay-to-Public-Key-Hash)',
    'P2WSH': '隔离见证付款到脚本哈希 (Segwit Pay-to-Script-Hash)',
    'P2TR': 'Taproot 输出 (Pay-to-Taproot)',
    'P2PK': '付款到公钥 (Pay-to-Public-Key)',
    'P2MS': '多重签名 (Multisig)',
    'OP_RETURN': '无法支付的数据输出 (Null Data)',
    'UNKNOWN': '未知类型'
};

// 解析脚本，转换为人类可读格式（已提供，无需修改）
function parseScript(script) {
    if (!script || script.length === 0) return '';
    
    let result = [];
    let i = 0;
    
    try {
        while (i < script.length) {
            const opcode = script[i];
            i++;
            
            if (opcode in OPCODES) {
                result.push(OPCODES[opcode]);
            } else if (opcode > 0 && opcode <= 0x4b) {
                const dataLength = opcode;
                if (i + dataLength <= script.length) {
                    const data = script.slice(i, i + dataLength).toString('hex');
                    result.push(`<${data}>`);
                    i += dataLength;
                } else {
                    result.push(`[无效数据推送: 长度超出范围]`);
                    break;
                }
            } else if (opcode >= 0x4c && opcode <= 0x4e) {
                let dataLength;
                let canProceed = true;
                
                if (opcode === 0x4c) {
                    if (i < script.length) {
                        dataLength = script[i];
                        i++;
                    } else {
                        result.push(`[无效 OP_PUSHDATA1: 缺少长度字节]`);
                        canProceed = false;
                    }
                } else if (opcode === 0x4d) {
                    if (i + 1 < script.length) {
                        dataLength = script.readUInt16LE(i);
                        i += 2;
                    } else {
                        result.push(`[无效 OP_PUSHDATA2: 缺少长度字节]`);
                        canProceed = false;
                    }
                } else {
                    if (i + 3 < script.length) {
                        dataLength = script.readUInt32LE(i);
                        i += 4;
                    } else {
                        result.push(`[无效 OP_PUSHDATA4: 缺少长度字节]`);
                        canProceed = false;
                    }
                }
                
                if (canProceed) {
                    if (i + dataLength <= script.length) {
                        const data = script.slice(i, i + dataLength).toString('hex');
                        result.push(`<${data}>`);
                        i += dataLength;
                    } else {
                        result.push(`[无效数据推送: 长度超出范围]`);
                        break;
                    }
                }
            } else {
                result.push(`[0x${opcode.toString(16).padStart(2, '0')}]`);
            }
        }
        
        return result.join(' ');
    } catch (error) {
        return `[脚本解析错误: ${error.message}]`;
    }
}

// 尝试识别脚本类型并提取地址（已提供，无需修改）
function analyzeScriptPubKey(scriptPubKey) {
    if (!scriptPubKey || scriptPubKey.length === 0) {
        return { type: 'INVALID', address: null, desc: '无效脚本' };
    }
    
    try {
        if (scriptPubKey[0] === 0x6a) {
            let data = '';
            if (scriptPubKey.length > 1) {
                const pushOp = scriptPubKey[1];
                let dataStart = 2;
                let dataLength = 0;
                
                if (pushOp <= 0x4b) {
                    dataLength = pushOp;
                } else if (pushOp === 0x4c) {
                    dataLength = scriptPubKey[2];
                    dataStart = 3;
                } else if (pushOp === 0x4d) {
                    dataLength = scriptPubKey.readUInt16LE(2);
                    dataStart = 4;
                }
                
                if (dataStart + dataLength <= scriptPubKey.length) {
                    data = scriptPubKey.slice(dataStart, dataStart + dataLength).toString('hex');
                }
            }
            
            return {
                type: 'OP_RETURN',
                address: null,
                desc: 'OP_RETURN 数据输出',
                data: data
            };
        }
        
        if (scriptPubKey.length === 25 && 
            scriptPubKey[0] === 0x76 && 
            scriptPubKey[1] === 0xa9 && 
            scriptPubKey[2] === 0x14 && 
            scriptPubKey[23] === 0x88 && 
            scriptPubKey[24] === 0xac) {
            
            const result = bitcoin.payments.p2pkh({
                hash: scriptPubKey.slice(3, 23),
                network: NETWORK
            });
            
            return {
                type: 'P2PKH',
                address: result.address,
                desc: SCRIPT_TYPES['P2PKH']
            };
        }
        
        if (scriptPubKey.length === 23 && 
            scriptPubKey[0] === 0xa9 && 
            scriptPubKey[1] === 0x14 && 
            scriptPubKey[22] === 0x87) {
            
            const result = bitcoin.payments.p2sh({
                hash: scriptPubKey.slice(2, 22),
                network: NETWORK
            });
            
            return {
                type: 'P2SH',
                address: result.address,
                desc: SCRIPT_TYPES['P2SH']
            };
        }
        
        if (scriptPubKey.length === 22 && 
            scriptPubKey[0] === 0x00 && 
            scriptPubKey[1] === 0x14) {
            
            const result = bitcoin.payments.p2wpkh({
                hash: scriptPubKey.slice(2, 22),
                network: NETWORK
            });
            
            return {
                type: 'P2WPKH',
                address: result.address,
                desc: SCRIPT_TYPES['P2WPKH']
            };
        }
        
        if (scriptPubKey.length === 34 && 
            scriptPubKey[0] === 0x00 && 
            scriptPubKey[1] === 0x20) {
            
            const result = bitcoin.payments.p2wsh({
                hash: scriptPubKey.slice(2, 34),
                network: NETWORK
            });
            
            return {
                type: 'P2WSH',
                address: result.address,
                desc: SCRIPT_TYPES['P2WSH']
            };
        }
        
        if (scriptPubKey.length === 34 && 
            scriptPubKey[0] === 0x51 && 
            scriptPubKey[1] === 0x20) {
            
            try {
                const result = bitcoin.payments.p2tr({
                    internalPubkey: scriptPubKey.slice(2, 34),
                    network: NETWORK
                });
                
                return {
                    type: 'P2TR',
                    address: result.address,
                    desc: SCRIPT_TYPES['P2TR']
                };
            } catch (e) {
                const witness_program = scriptPubKey.slice(2, 34);
                try {
                    const address = bitcoin.address.toBech32(witness_program, 1, NETWORK.bech32);
                    return {
                        type: 'P2TR',
                        address: address,
                        desc: SCRIPT_TYPES['P2TR'] + ' (推导)'
                    };
                } catch (e2) {}
            }
        }
        
        if ((scriptPubKey.length === 67 || scriptPubKey.length === 35) && 
            (scriptPubKey[0] === 0x41 || scriptPubKey[0] === 0x21) && 
            scriptPubKey[scriptPubKey.length - 1] === 0xac) {
            
            const pubkeyLength = scriptPubKey[0] - 0x50;
            const pubkey = scriptPubKey.slice(1, 1 + pubkeyLength);
            
            try {
                const p2pkhResult = bitcoin.payments.p2pkh({
                    pubkey: pubkey,
                    network: NETWORK
                });
                
                return {
                    type: 'P2PK',
                    address: p2pkhResult.address + ' (等效 P2PKH)',
                    desc: SCRIPT_TYPES['P2PK']
                };
            } catch (e) {
                return {
                    type: 'P2PK',
                    address: null,
                    desc: SCRIPT_TYPES['P2PK'] + ' (无法提取地址)'
                };
            }
        }
        
        if (scriptPubKey.length >= 37 && scriptPubKey[scriptPubKey.length - 1] === 0xae) {
            return {
                type: 'P2MS',
                address: null,
                desc: SCRIPT_TYPES['P2MS']
            };
        }
        
        try {
            let address = null;
            try {
                const result = bitcoin.payments.p2pkh({ output: scriptPubKey, network: NETWORK });
                if (result.address) address = result.address;
            } catch (e) {}
            
            if (!address) {
                try {
                    const result = bitcoin.payments.p2sh({ output: scriptPubKey, network: NETWORK });
                    if (result.address) address = result.address;
                } catch (e) {}
            }
            
            if (!address) {
                try {
                    const result = bitcoin.payments.p2wpkh({ output: scriptPubKey, network: NETWORK });
                    if (result.address) address = result.address;
                } catch (e) {}
            }
            
            if (!address) {
                try {
                    const result = bitcoin.payments.p2wsh({ output: scriptPubKey, network: NETWORK });
                    if (result.address) address = result.address;
                } catch (e) {}
            }
            
            if (!address) {
                try {
                    const result = bitcoin.payments.p2tr({ output: scriptPubKey, network: NETWORK });
                    if (result.address) address = result.address;
                } catch (e) {}
            }
            
            if (address) {
                return {
                    type: 'UNKNOWN',
                    address: address,
                    desc: '未知脚本类型 (地址已提取)'
                };
            }
        } catch (e) {}
        
        return {
            type: 'UNKNOWN',
            address: null,
            desc: '无法识别的脚本类型'
        };
    } catch (e) {
        return {
            type: 'ERROR',
            address: null,
            desc: `解析错误: ${e.message}`
        };
    }
}

// 美化显示金额（已提供，无需修改）
function formatBitcoinAmount(satoshis) {
    const btc = satoshis / 100000000;
    return `${satoshis.toLocaleString()} 聪 (${btc.toFixed(8)} BTC)`;
}

// 主解码函数
function decodeTransaction() {
    const rawTxHex = document.getElementById('rawTxInput').value.trim();
    const resultDiv = document.getElementById('result');
    const notification = document.getElementById('notification');
    const resultsContainer = document.getElementById('resultsContainer');
    const txSummaryDiv = document.getElementById('txSummary');
    const txInputsDiv = document.getElementById('txInputs');
    const txOutputsDiv = document.getElementById('txOutputs');
    const rawTxDataDiv = document.getElementById('rawTxData');

    // 清空之前的输出
    resultDiv.innerHTML = '';
    notification.innerHTML = '';
    txSummaryDiv.innerHTML = '';
    txInputsDiv.innerHTML = '';
    txOutputsDiv.innerHTML = '';
    rawTxDataDiv.innerHTML = '';

    if (!rawTxHex) {
        notification.innerHTML = '<div class="error">请输入有效的交易十六进制数据！</div>';
        resultsContainer.style.display = 'none';
        return;
    }

    try {
        // 解析交易
        const tx = bitcoin.Transaction.fromHex(rawTxHex);
        const txId = tx.getId();
        const rawTxBuffer = Buffer.from(rawTxHex, 'hex');
        const txSize = rawTxBuffer.length;
        const hasWitness = tx.hasWitnesses();

        // 检查 RBF
        const isRBF = tx.ins.some(input => input.sequence < 0xffffffff - 1);

        // 计算虚拟大小 (vsize)
        let vsize = txSize;
        if (hasWitness) {
            let weight = txSize * 4;
            const witnessBytes = tx.ins.reduce((sum, input) => {
                return sum + input.witness.reduce((wsum, item) => wsum + item.length, 0);
            }, 0);
            weight = weight - (witnessBytes * 3);
            vsize = Math.ceil(weight / 4);
        }

        // 构建文本解码结果
        let output = `=== 交易基本信息 ===\n`;
        output += `交易ID (TxID): ${txId}\n`;
        output += `版本号 (Version): ${tx.version}\n`;
        output += `交易大小 (Size): ${txSize} 字节\n`;
        if (hasWitness) {
            output += `虚拟大小 (vSize): ${vsize} vB\n`;
        }
        output += `是否有隔离见证数据: ${hasWitness ? '是' : '否'}\n`;
        output += `Replace-By-Fee (RBF): ${isRBF ? '是' : '否'}\n`;

        // 交易摘要（可视化）
        let totalOutputValue = 0;
        tx.outs.forEach(out => totalOutputValue += out.value);

        txSummaryDiv.innerHTML = `
            <div class="tx-meta">
                <div class="tx-meta-item">
                    <div class="tx-meta-label">交易ID</div>
                    <div class="tx-meta-value">${txId} <button class="copy-btn" onclick="copyToClipboard('${txId}')">[复制]</button></div>
                </div>
                <div class="tx-meta-item">
                    <div class="tx-meta-label">版本号</div>
                    <div class="tx-meta-value">${tx.version}</div>
                </div>
                <div class="tx-meta-item">
                    <div class="tx-meta-label">大小</div>
                    <div class="tx-meta-value">${txSize} 字节 ${hasWitness ? `(${vsize} vB)` : ''}</div>
                </div>
                <div class="tx-meta-item">
                    <div class="tx-meta-label">总输出金额</div>
                    <div class="tx-meta-value">${formatBitcoinAmount(totalOutputValue)}</div>
                </div>
            </div>
        `;

        // 解析输入
        output += `\n=== 输入 (${tx.ins.length}) ===\n`;
        tx.ins.forEach((input, index) => {
            const txHash = Buffer.from(input.hash).reverse().toString('hex');
            const vout = input.index;
            const scriptSig = input.script.toString('hex');
            const sequence = input.sequence;

            output += `\n输入 #${index}:\n`;
            output += `  来源交易: ${txHash}\n`;
            output += `  输出索引 (vout): ${vout}\n`;
            output += `  序列号: ${sequence} (0x${sequence.toString(16)})\n`;

            if (scriptSig) {
                output += `  解锁脚本 (ScriptSig): ${scriptSig}\n`;
                output += `  解析脚本: ${parseScript(input.script)}\n`;
            } else {
                output += `  解锁脚本: [空]\n`;
            }

            if (input.witness && input.witness.length > 0) {
                output += `  见证数据 (Witness):\n`;
                input.witness.forEach((item, i) => {
                    output += `    [${i}] ${item.toString('hex')}\n`;
                });
            }

            // 可视化输入
            let witnessData = '';
            if (input.witness && input.witness.length > 0) {
                witnessData = input.witness.map((item, i) => `<div>[${i}] ${item.toString('hex')}</div>`).join('');
            }
            const inputHtml = `
                <div class="tx-item">
                    <div class="tx-item-header">
                        输入 #${index}
                        <button class="copy-btn" onclick="copyToClipboard('${txHash}')">[复制来源交易ID]</button>
                    </div>
                    <div class="tx-item-content">
                        <div><strong>来源交易:</strong> ${txHash}</div>
                        <div><strong>输出索引:</strong> ${vout}</div>
                        <div><strong>序列号:</strong> ${sequence} (0x${sequence.toString(16)})</div>
                        <div><strong>解锁脚本:</strong> ${scriptSig || '[空]'}</div>
                        ${scriptSig ? `<div><strong>解析脚本:</strong> ${parseScript(input.script)}</div>` : ''}
                        ${witnessData ? `<div><strong>见证数据:</strong><div>${witnessData}</div></div>` : ''}
                    </div>
                </div>
            `;
            txInputsDiv.innerHTML += inputHtml;
        });

        // 解析输出
        output += `\n=== 输出 (${tx.outs.length}) ===\n`;
        tx.outs.forEach((out, index) => {
            const value = out.value;
            const scriptPubKey = out.script;
            const scriptAnalysis = analyzeScriptPubKey(scriptPubKey);

            output += `\n输出 #${index}:\n`;
            output += `  金额: ${formatBitcoinAmount(value)}\n`;
            output += `  锁定脚本 (ScriptPubKey): ${scriptPubKey.toString('hex')}\n`;
            output += `  解析脚本: ${parseScript(scriptPubKey)}\n`;
            output += `  类型: ${scriptAnalysis.type}\n`;
            output += `  描述: ${scriptAnalysis.desc}\n`;
            if (scriptAnalysis.address) {
                output += `  地址: ${scriptAnalysis.address}\n`;
            }
            if (scriptAnalysis.data) {
                output += `  数据: ${scriptAnalysis.data}\n`;
            }

            // 可视化输出
            const outputHtml = `
                <div class="tx-item">
                    <div class="tx-item-header">
                        输出 #${index}
                        ${scriptAnalysis.address ? `<button class="copy-btn" onclick="copyToClipboard('${scriptAnalysis.address}')">[复制地址]</button>` : ''}
                    </div>
                    <div class="tx-item-content">
                        <div><strong>金额:</strong> ${formatBitcoinAmount(value)}</div>
                        <div><strong>类型:</strong> ${scriptAnalysis.type} (${scriptAnalysis.desc})</div>
                        ${scriptAnalysis.address ? `<div><strong>地址:</strong> ${scriptAnalysis.address}</div>` : ''}
                        ${scriptAnalysis.data ? `<div><strong>数据:</strong> ${scriptAnalysis.data}</div>` : ''}
                        <div><strong>锁定脚本:</strong> ${scriptPubKey.toString('hex')}</div>
                        <div><strong>解析脚本:</strong> ${parseScript(scriptPubKey)}</div>
                    </div>
                </div>
            `;
            txOutputsDiv.innerHTML += outputHtml;
        });

        // 锁时间
        output += `\n=== 其他信息 ===\n`;
        output += `锁时间 (Locktime): ${tx.locktime}\n`;

        // 原始交易数据
        rawTxDataDiv.textContent = rawTxHex;

        // 显示结果
        resultDiv.textContent = output;
        resultsContainer.style.display = 'block';
        notification.innerHTML = '<div class="success">交易解码成功！</div>';

    } catch (error) {
        notification.innerHTML = `<div class="error">解码失败：${error.message}</div>`;
        resultsContainer.style.display = 'none';
    }
}

// 清空输入框
function clearInput() {
    document.getElementById('rawTxInput').value = '';
    document.getElementById('resultsContainer').style.display = 'none';
    document.getElementById('notification').innerHTML = '';
}

// 加载示例交易
function loadSampleTx() {
    // 一个简单的比特币主网交易（P2PKH，非隔离见证）
    const sampleTx = '020000000001018f105811203439c1a1f0325eb553eb7dc7ddfb11f434bf8dfb640f1244eea4df0000000000ffffffff021010e9000000000016001456d46899fe8a6d2694abe1294d14888ccebb66bfd79c4122000000001600149c38191f20275ea9ececd2f762c450ff159508f802473044022070181cd1291be94ae0ef7976ffc77a9644f223e0a91c0059c364ecf148809e3202203be57465271368a823410a1a3578c761c6cb2cd582871ec4064e4a336c0121cb012103e6bbd3f40f01ddd7587915a514c30998561d26abf8baf1cc53ac1360fae860f600000000';
    document.getElementById('rawTxInput').value = sampleTx;
    document.getElementById('notification').innerHTML = '<div class="success">示例交易已加载！</div>';
}

// 复制到剪贴板
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        alert('已复制到剪贴板！');
    }).catch(err => {
        console.error('复制失败:', err);
    });
}

// 选项卡切换逻辑
document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
        // 移除所有激活状态
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

        // 添加当前激活状态
        tab.classList.add('active');
        const tabId = tab.getAttribute('data-tab');
        document.getElementById(tabId).classList.add('active');
    });
});

window.decodeTransaction = decodeTransaction;
window.clearInput = clearInput;
window.loadSampleTx = loadSampleTx;
window.copyToClipboard = copyToClipboard;