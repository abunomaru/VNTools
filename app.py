#!/usr/bin/env python3
"""
VNTools Web GUI - Flask Backend
Provides REST API endpoints for all VNTools functionality
"""

import os
import sys
import json
import tempfile
import shutil
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename
import systemnnn_tools as vn

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
        writer = vn.DDPWriter(output_path)

        # Add all files from directory
        for root, dirs, files in os.walk(input_dir):
            for f in files:
                file_path = os.path.join(root, f)
                archive_path = os.path.relpath(file_path, input_dir)
                with open(file_path, 'rb') as fp:
                    writer.add_file(archive_path, fp.read())

        writer.write()

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

        # Determine script type and decrypt
        if script_type == 'hxb':
            script = vn.HXBScript.from_file(filepath)
            output_ext = '.txt'
        elif script_type == 'spt':
            script = vn.SPTScript.from_file(filepath)
            output_ext = '.txt'
        elif script_type == 'nnn':
            script = vn.NNNScript.from_file(filepath)
            output_ext = '.txt'
        else:
            return jsonify({'error': 'Invalid script type'}), 400

        # Save decrypted content
        output_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{filename}{output_ext}")
        with open(output_path, 'wb') as f:
            f.write(script.content)

        # Read content for preview
        preview = script.content.decode('utf-16-le' if script_type == 'hxb' else 'shift-jis', errors='replace')[:1000]

        return jsonify({
            'success': True,
            'message': 'Script decrypted successfully',
            'preview': preview,
            'output_path': output_path
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

        # Encrypt based on type
        if script_type == 'hxb':
            script = vn.HXBScript(content)
            output_ext = '.hxb'
        elif script_type == 'spt':
            script = vn.SPTScript(content)
            output_ext = '.spt'
        else:
            return jsonify({'error': 'Invalid script type'}), 400

        # Save encrypted file
        output_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{filename}{output_ext}")
        script.to_file(output_path)

        return jsonify({
            'success': True,
            'message': 'Script encrypted successfully',
            'output_path': output_path
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

        # Extract text
        vn.extract_text(filepath, output_path)

        # Read extracted text for preview
        with open(output_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        return jsonify({
            'success': True,
            'message': f'Extracted {len(data)} text strings',
            'count': len(data),
            'preview': data[:10] if len(data) > 10 else data,
            'output_path': output_path
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/translate', methods=['POST'])
def translate():
    """Translate JSON file using LLM"""
    try:
        data = request.get_json()

        # Get parameters
        input_file = data.get('input_file')
        provider = data.get('provider', 'openai')
        api_key = data.get('api_key')
        model = data.get('model', 'gpt-4')
        source_lang = data.get('source_lang', 'Japanese')
        target_lang = data.get('target_lang', 'English')

        # Translation settings
        use_sjis_tunnel = data.get('use_sjis_tunnel', False)
        use_dictionary = data.get('use_dictionary', False)
        dictionary_file = data.get('dictionary_file')
        use_qa = data.get('use_qa', True)

        if not input_file or not os.path.exists(input_file):
            return jsonify({'error': 'Invalid input file'}), 400

        if not api_key:
            return jsonify({'error': 'API key required'}), 400

        # Create translator
        if provider == 'openai':
            translator = vn.OpenAITranslator(api_key, model)
        elif provider == 'anthropic':
            translator = vn.AnthropicTranslator(api_key, model)
        elif provider == 'deepl':
            translator = vn.DeepLTranslator(api_key)
        else:
            return jsonify({'error': 'Invalid provider'}), 400

        # Set up SJIS tunnel if enabled
        sjis_tunnel = vn.SJISTunnelEncoder() if use_sjis_tunnel else None

        # Load dictionary if enabled
        gpt_dict = None
        if use_dictionary and dictionary_file and os.path.exists(dictionary_file):
            gpt_dict = vn.GPTDictionary.from_file(dictionary_file)

        # Set up QA
        qa = vn.TranslationQA() if use_qa else None

        output_file = input_file.replace('.json', '_translated.json')

        # Translate (this is a simplified version - full implementation would need async handling)
        vn.translate_json_file(
            input_file,
            output_file,
            translator,
            source_lang=source_lang,
            target_lang=target_lang,
            gpt_dict=gpt_dict,
            sjis_tunnel=sjis_tunnel,
            qa=qa
        )

        return jsonify({
            'success': True,
            'message': 'Translation completed',
            'output_path': output_file
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

        output_path = script_file.replace('.', '_translated.')

        # Insert text
        vn.insert_text(script_file, json_file, output_path)

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

        for entry in archive.entries:
            files_info.append({
                'path': entry.path,
                'size': entry.size,
                'compressed_size': entry.compressed_size,
                'compression_ratio': f"{(1 - entry.compressed_size / entry.size) * 100:.1f}%" if entry.size > 0 else "0%"
            })
            total_size += entry.size

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
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if os.path.exists(filepath):
            return send_file(filepath, as_attachment=True)
        else:
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
            'encoded': encoded,
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
        if mapping:
            encoder.mapping = {int(k): v for k, v in mapping.items()}

        decoded = encoder.decode(text)

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

        wrapper = vn.WordWrapper(max_width=max_width, font_type=font_type)
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
    print("Starting server on http://localhost:5000")
    print("Press Ctrl+C to stop")
    print("=" * 60)
    app.run(debug=True, host='0.0.0.0', port=5000)
