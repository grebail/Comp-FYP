const net = require('net');
const { MongoClient } = require('mongodb');

const uri = 'mongodb+srv://TestUser:wquPzBcNKUZDRYXr@cluster0.4ibja.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';
const client = new MongoClient(uri);

async function updateBookStatus(epc) {
    try {
        await client.connect();
        const database = client.db('Library'); // 使用現有的數據庫
        const collection = database.collection('books'); // 使用現有的集合
        const book = await collection.findOne({ epc: epc });

        // Output the result
        if (book) {
            await collection.updateOne(
                { epc: epc },
                { $set: { status: 'in return box' } }
            );
            console.log(`Updated status for book with EPC: ${epc}`);
            //呢度可以加send email比user or 圖書館提醒本書已經放左入還書箱
        } else {
            console.log(`Book with EPC: ${epc} not found.`);
        }
    } catch (error) {
        console.error('Error updating book status:', error);
    } finally {
        await client.close();
    }
}

function extractMiddleSegment(data) {
    if (typeof data === 'string' && data.length >= 8) {
        return data.substring(8, 16); // 提取從第 4 個字符到第 8 個字符（包含第 8 個）
    }
    return null; 
}

const processedEpcs = new Set(); // Set to track processed EPCs

function startRfidServer(host = '0.0.0.0', port = 65432) {
    const server = net.createServer((connection) => {
        console.log(`Connected by ${connection.remoteAddress}:${connection.remotePort}`);

        connection.on('data', async (data) => {
            try {
                const hexData = data.toString('hex').toUpperCase();
                const middleSegment = extractMiddleSegment(hexData);

                if (middleSegment) {
                    // Check if this EPC has already been processed
                    if (!processedEpcs.has(middleSegment)) {
                        await updateBookStatus(middleSegment);
                        processedEpcs.add(middleSegment); // Mark this EPC as processed
                    } else {
                        console.log(`EPC ${middleSegment} has already been processed.`);
                    }
                } else {
                    console.log('No valid middle segment found.');
                }
            } catch (error) {
                console.error('Error processing data:', error);
            }
        });

        connection.on('end', () => {
            console.log(`Disconnected from ${connection.remoteAddress}:${connection.remotePort}`);
        });
    });

    server.listen(port, host, () => {
        console.log(`Listening for RFID data on ${host}:${port}...`);
    });

    // Handle shutdown gracefully
    process.on('SIGINT', () => {
        server.close(() => {
            console.log('Server closed.');
            process.exit(0);
        });
    });
}
startRfidServer();