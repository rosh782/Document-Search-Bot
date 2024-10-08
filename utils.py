import openai
import docx
import os
from flask import current_app
import pdfplumber
import fitz

openai.api_key = "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"

def file_creation():
    if not os.path.exists(current_app.config['TEXTFILE_FOLDER']):
        os.makedirs(current_app.config['TEXTFILE_FOLDER'])


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']


def convert_pdf_to_txt(filepath):
    text = ""

    # First attempt with pdfplumber
    try:
        with pdfplumber.open(filepath) as pdf:
            for page in pdf.pages:
                page_text = page.extract_text()
                if page_text:
                    text += page_text
    except Exception as e:
        print(f"pdfplumber error: {e}")

    # Fallback to PyMuPDF if needed
    if not text:
        try:
            pdf_document = fitz.open(filepath)
            for page_num in range(len(pdf_document)):
                page = pdf_document.load_page(page_num)
                text += page.get_text()
            pdf_document.close()
        except Exception as e:
            print(f"PyMuPDF error: {e}")

    return text

def convert_docx_to_txt(filepath):
    doc = docx.Document(filepath)
    text = ""
    for paragraph in doc.paragraphs:
        text += paragraph.text + "\n"
    return text

def save_file_content(filename, content):
    txt_filename = filename.rsplit('.', 1)[0] + '.txt'
    new_filepath = os.path.join(current_app.config['TEXTFILE_FOLDER'], txt_filename)
    with open(new_filepath, 'w', encoding='utf-8') as f:
        f.write(content)


def ask_question(text_context, question):
    try:
        # Call GPT-3.5 Turbo to answer the question
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": f"Text: {text_context}\n\nQuestion: {question}"}
            ]
        )
        # Extract the response from GPT
        answer = response['choices'][0]['message']['content'].strip()
        return answer

    except openai.OpenAIError as e:  # Corrected exception handling
        return f"An error occurred while getting the answer: {str(e)}"
# Example usage


# text_context = "The capital of France is Paris. It is known for its art, fashion, and culture."
# question = "What is the france known for?"
#
# answer = ask_question(text_context, question)
# print(answer)

