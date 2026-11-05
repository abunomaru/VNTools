#!/usr/bin/env python3
"""
VNTools Web GUI - Flask Backend
Provides REST API endpoints for all VNTools functionality
"""

import os
import json
import tempfile
from flask import Flask, render_template, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename
from werkzeug.exceptions import NotFound
import systemnnn_tools as vn
import nnn_engine as nne

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max file size
app.config['UPLOAD_FOLDER'] = tempfile.mkdtemp()

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@app.route('/')
def index():
    """Serve the main GUI"""
    return render_template('index.html')

@app.route('/api/extract-archive', methods=['POST'])
def extract_archive():
    """Extract DDP archive"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        # Save uploaded file
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # Create output directory
        output_dir = os.path.join(app.config['UPLOAD_FOLDER'], f"{filename}_extracted")
        os.makedirs(output_dir, exist_ok=True)

        # Extract archive
        archive = vn.DDPArchive(filepath)
        if not archive.open():
            return jsonify({'error': 'Not a DDP2/DDP3 archive'}), 400
        archive.extract_all(output_dir)

        # Get list of extracted files
        extracted_files = []
        for root, dirs, files in os.walk(output_dir):
            for f in files:
                rel_path = os.path.relpath(os.path.join(root, f), output_dir)
                extracted_files.append(rel_path)

        return jsonify({
            'success': True,
            'message': f'Extracted {len(extracted_files)} files',
            'files': extracted_files,
            'output_path': output_dir
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/repack-archive', methods=['POST'])
def repack_archive():
    """Repack files into DDP archive"""
    try:
        data = request.get_json()
        input_dir = data.get('input_dir')
        output_name = data.get('output_name', 'repacked.ddp')

        if not input_dir or not os.path.exists(input_dir):
            return jsonify({'error': 'Invalid input directory'}), 400

        output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_name)

        # Create archive
        writer = vn.DDPWriter(3)

        # Add all files from directory
        for root, dirs, files in os.walk(input_dir):
            for f in files:
                file_path = os.path.join(root, f)
                archive_path = os.path.relpath(file_path, input_dir)
                with open(file_path, 'rb') as fp:
                    writer.add_file(archive_path, fp.read())

        writer.write(output_path)

        return jsonify({
            'success': True,
            'message': 'Archive repacked successfully',
            'output_path': output_path
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/decrypt-script', methods=['POST'])
def decrypt_script():
    """Decrypt HXB or SPT script"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']
        script_type = request.form.get('type', 'hxb')

        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        with open(filepath, 'rb') as f:
            data = f.read()
        if script_type == 'hxb':
            if data[:4] == b'DDWu':
                content = vn.decrypt_hxb(vn.fix_hxb_signature(data))
            else:
                content = data  # DDSx files are stored unencrypted
            preview = content.decode('utf-16-le', errors='replace')[:1000]
        elif script_type == 'spt':
            content = nne.nnn_decrypt(data)
            preview = content.decode('cp932', errors='replace')[:1000]
        elif script_type == 'nnn':
            content = data
            preview = content.decode('cp932', errors='replace')[:1000]
        else:
            return jsonify({'error': 'Invalid script type'}), 400

        output_name = f"{filename}.dec"
        with open(os.path.join(app.config['UPLOAD_FOLDER'], output_name), 'wb') as f:
            f.write(content)

        return jsonify({
            'success': True,
            'message': 'Script decrypted successfully',
            'preview': preview,
            'output_path': output_name
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/encrypt-script', methods=['POST'])
def encrypt_script():
    """Encrypt script to HXB or SPT format"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']
        script_type = request.form.get('type', 'hxb')

        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # Read content
        with open(filepath, 'rb') as f:
            content = f.read()

        if script_type == 'hxb':
            out = vn.encrypt_hxb(content)
            output_ext = '.hxb'
        elif script_type == 'spt':
            out = nne.nnn_encrypt(content)
            output_ext = '.spt'
        else:
            return jsonify({'error': 'Invalid script type'}), 400

        output_name = f"{os.path.splitext(filename)[0]}{output_ext}"
        with open(os.path.join(app.config['UPLOAD_FOLDER'], output_name), 'wb') as f:
            f.write(out)

        return jsonify({
            'success': True,
            'message': 'Script encrypted successfully',
            'output_path': output_name
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/extract-text', methods=['POST'])
def extract_text():
    """Extract translatable text from scripts"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        output_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{filename}.json")

        if not vn.extract_text_with_format(filepath, output_path):
            return jsonify({'error': 'Unknown or unparseable script'}), 400

        with open(output_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        strings = data.get('strings', []) if isinstance(data, dict) else data

        return jsonify({
            'success': True,
            'message': f'Extracted {len(strings)} text strings',
            'count': len(strings),
            'preview': strings[:10],
            'output_path': output_path
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/translate', methods=['POST'])
def translate():
    """Translate JSON file using LLM"""
    try:
        data = request.get_json()

        input_file = data.get('input_file')
        provider = data.get('provider', 'anthropic')
        api_key = data.get('api_key') or os.environ.get(vn.llm.API_KEY_ENV.get(provider, ''), '')
        model = data.get('model', '')
        target_lang = data.get('target_lang', 'English')
        use_dictionary = data.get('use_dictionary', False)
        dictionary_file = data.get('dictionary_file')
        use_qa = data.get('use_qa', True)

        if not input_file or not os.path.exists(input_file):
            return jsonify({'error': 'Invalid input file'}), 400
        if not api_key and provider != 'openai-compatible':
            return jsonify({'error': 'API key required'}), 400
        if provider not in ('anthropic', 'openai', 'openai-compatible', 'deepl'):
            return jsonify({'error': 'Invalid provider'}), 400

        dictionary = None
        if use_dictionary and dictionary_file and os.path.exists(dictionary_file):
            dictionary = vn.GPTDictionary(dictionary_file)

        translator = vn.make_chunk_translator(
            provider, api_key=api_key, model=model, base_url=data.get('base_url', ''),
            target_lang=target_lang, dictionary=dictionary,
            dict_context=os.path.splitext(os.path.basename(input_file))[0])

        output_file = input_file.replace('.json', '_translated.json')
        vn.translate_json_file(input_file, output_file, translator, dictionary)

        qa_issues = None
        if use_qa:
            qa_issues = vn.qa_cli(output_file, dictionary=dictionary)

        return jsonify({
            'success': True,
            'message': 'Translation completed',
            'output_path': output_file,
            'qa_issues': qa_issues
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/insert-text', methods=['POST'])
def insert_text():
    """Insert translated text back into script"""
    try:
        data = request.get_json()

        script_file = data.get('script_file')
        json_file = data.get('json_file')

        if not script_file or not os.path.exists(script_file):
            return jsonify({'error': 'Invalid script file'}), 400

        if not json_file or not os.path.exists(json_file):
            return jsonify({'error': 'Invalid JSON file'}), 400

        root, ext = os.path.splitext(script_file)
        output_path = root + '_translated' + ext

        vn.insert_text_cli(script_file, json_file, output_path,
                           wrap=str(data.get('wrap', 'auto')),
                           code_byte=int(data.get('code_byte', 2)))

        return jsonify({
            'success': True,
            'message': 'Text inserted successfully',
            'output_path': output_path
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analyze-archive', methods=['POST'])
def analyze_archive():
    """Analyze archive structure"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # Open archive
        archive = vn.DDPArchive(filepath)

        # Gather file information
        files_info = []
        total_size = 0

        if not archive.open():
            return jsonify({'error': 'Not a DDP2/DDP3 archive'}), 400

        for entry in archive.entries:
            packed = entry.packed_size if entry.is_packed else entry.unpacked_size
            files_info.append({
                'path': entry.name,
                'size': entry.unpacked_size,
                'compressed_size': packed,
                'compression_ratio': f"{(1 - packed / entry.unpacked_size) * 100:.1f}%" if entry.unpacked_size > 0 else "0%"
            })
            total_size += entry.unpacked_size

        return jsonify({
            'success': True,
            'file_count': len(archive.entries),
            'total_size': total_size,
            'files': files_info
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/download/<path:filename>')
def download_file(filename):
    """Download a processed file"""
    try:
        # send_from_directory refuses paths that escape the upload folder
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
    except NotFound:
        return jsonify({'error': 'File not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/sjis-tunnel/encode', methods=['POST'])
def sjis_tunnel_encode():
    """Encode text using SJIS tunneling"""
    try:
        data = request.get_json()
        text = data.get('text', '')

        encoder = vn.SJISTunnelEncoder()
        encoded = encoder.encode(text)
        mapping = encoder.get_mapping()

        return jsonify({
            'success': True,
            'encoded': encoded.hex(' '),
            'mapping': mapping
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/sjis-tunnel/decode', methods=['POST'])
def sjis_tunnel_decode():
    """Decode SJIS tunneled text"""
    try:
        data = request.get_json()
        text = data.get('text', '')
        mapping = data.get('mapping', {})

        encoder = vn.SJISTunnelEncoder()
        # mapping is {"hex tunnel code": char} as returned by /encode, in order
        for _code, ch in mapping.items():
            encoder.tunnel_bytes(ch)

        decoded = encoder.decode(bytes.fromhex(text.replace(' ', '')))

        return jsonify({
            'success': True,
            'decoded': decoded
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/word-wrap', methods=['POST'])
def word_wrap():
    """Apply word wrapping to text"""
    try:
        data = request.get_json()
        text = data.get('text', '')
        max_width = int(data.get('max_width', 40))
        font_type = data.get('font_type', 'monospace')

        wrapper = vn.WordWrapper(chars_per_line=max_width, mode=font_type)
        wrapped = wrapper.wrap(text)

        return jsonify({
            'success': True,
            'wrapped': wrapped
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/convert-format', methods=['POST'])
def convert_format():
    """Convert between JSON formats"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']
        target_format = request.form.get('format', 'vnt')

        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        output_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{filename}_converted.json")

        # Convert format
        if target_format == 'vnt':
            vn.convert_to_vnt_format(filepath, output_path)
        else:
            return jsonify({'error': 'Invalid target format'}), 400

        return jsonify({
            'success': True,
            'message': 'Format converted successfully',
            'output_path': output_path
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("=" * 60)
    print("VNTools Web GUI")
    print("=" * 60)
    host = os.environ.get('VNTOOLS_HOST', '127.0.0.1')
    print(f"Starting server on http://{host}:5000")
    print("Press Ctrl+C to stop")
    print("=" * 60)
    # Debug mode exposes the Werkzeug debugger (remote code execution), so it is
    # opt-in, and the server only listens on localhost unless VNTOOLS_HOST is set.
    app.run(debug=os.environ.get('VNTOOLS_DEBUG') == '1', host=host, port=5000)
