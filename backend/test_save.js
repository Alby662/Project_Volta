// Use the built-in fetch if available, otherwise require node-fetch
const fetch = global.fetch || require('node-fetch');

async function testSaveReport() {
  try {
    const response = await fetch('http://localhost:5000/api/save-report', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        reportType: 'liquid',
        reportTitle: 'Test Report',
        formData: {
          reportName: 'Test Report',
          logo_select: '/images/volta green.png',
          // Add some sample form data
          test_field: 'test value'
        }
      }),
    });

    const data = await response.json();
    console.log('Response:', data);
  } catch (error) {
    console.error('Error:', error);
  }
}

testSaveReport();