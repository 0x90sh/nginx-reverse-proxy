local _M = {}

_M.sql_injection_pattern = [[\b(?i:union|select|insert|update|delete|drop|alter|truncate|grant|exec|sp_executesql|execute|create|declare|backup|restore)\b[\s\S]*?\b(?i:from|into|table|database|procedure|function|view|exec|execute|where|values|set)\b]]
_M.sql_injection_generic_union_pattern = [[\b(?i:UNION\s+(?:ALL\s+)?SELECT)\b[\s\S]*?(\d+)[\s\S]*?]]
_M.sql_injection_time_based_pattern = [[\b(?i:(?:sleep\(\s*\d+\s*\)|benchmark\(\s*\d+\s*,\s*MD5\(\s*\d+\s*\))|pg_sleep\(\s*\d+\s*\)|waitfor\s+delay\s+'(?:\d+:\d+:\d+|\d+)'))\b]]
_M.sqli_error_pattern = [=[\b(?i:(?:\d+=[\d'"]+|x=x|x=y|x\s*=[\w'"]+|\d+=\d+|\d+\s*=[\w'"]+|HAVING\s+\d+=\d+|HAVING\s+\d+\s*=[\w'"]+|AND\s+\d+=\d+|AND\s+\d+\s*=[\w'"]+|AND\s+\d+=\d+\s+AND\s+'%'='%'|AND\s+\d+\s*=[\w'"]+\s+AND\s+'%'='%'|AS\s+INJECTX\s+WHERE\s+\d+=\d+\s+AND\s+\d+=\d+|AS\s+INJECTX\s+WHERE\s+\d+\s*=[\w'"]+\s+AND\s+\d+\s*=[\w'"]+|WHERE\s+\d+=\d+\s+AND\s+\d+=\d+|WHERE\s+\d+\s*=[\w'"]+\s+AND\s+\d+\s*=[\w'"]+|ORDER\s+BY\s+\d+--|ORDER\s+BY\s+\d+#|ORDER\s+BY\s+\d+|RLIKE\s+\(SELECT\s+\(CASE\s+WHEN\s+\(\d+=\d+\)\s+THEN\s+0x61646d696e\s+ELSE\s+0x28\s+END\)\)\s+AND\s+'\w{4}'='\w{4}'|IF\(\d+=\d+\)\s+SELECT\s+\d+\s+ELSE\s+DROP\s+FUNCTION\s+\w+\-\-|\%'.*?\d+=\d+.*?'[\s\S]*?AND\s+'%'='%'))\b]=]
_M.xss_pattern = [[(<script.*?>.*?</script>|<script.*?>|</script>|<.*?javascript:.*?>|<.*? on.*?=|<.*?data-.*?=|javascript:|document\.write\(.*?\)|eval\(.*?\)|expression\(.*?\)|<.*?url\(.*?\)|<.*?postMessage\(.*?\)|localStorage\(.*?\)|sessionStorage\(.*?\)|<.*?createContextualFragment\(.*?\))]]

_M.failed = [[
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>500 Internal Server Error</title>
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Roboto:wght@400;500&display=swap');
    
            body {
                font-family: 'Roboto', sans-serif;
                background-color: #ffffff;
                color: #333333;
                margin: 0;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                overflow: hidden;
            }
            .container {
                text-align: center;
                display: flex;
                flex-direction: column;
                align-items: center;
                animation: fadeIn 1s ease-in-out;
            }
            .content {
                display: flex;
                align-items: center;
                justify-content: center;
                position: relative;
                margin-bottom: 15px;
                padding: 6px 12px;
                background-color: rgba(0, 0, 0, 0);
                animation: fillBackground 2s ease-in-out forwards;
                animation-delay: 1s;
                width: 90%%;
                height: 80%%;
            }
            .red-line {
                position: absolute;
                height: 100%%;
                width: 3px;
                background-color: #B22222;
                left: 100%%;
                animation: slideInRedLine 1s ease-in-out forwards;
            }
            .text-wrapper {
                display: flex;
                align-items: center;
                padding: 0 8px;
                position: relative;
            }
            .text-content {
                display: flex;
                align-items: center;
                position: relative;
                z-index: 1;
            }
            .text-content h1 {
                font-size: 22.4px;
                margin: 0;
                font-weight: 500;
            }
            .text-content h2 {
                font-size: 22.4px;
                margin: 0;
                font-weight: 500;
                padding-left: 8px;
            }
            .info-compartment {
                font-size: 12.8px;
                color: #666666;
                border-top: 1px solid #e0e0e0;
                padding-top: 8px;
                font-family: 'Roboto', sans-serif;
            }
            .disclaimer {
                font-size: 12.8px;
                color: #666666;
                padding-bottom: 4px;
                font-family: 'Roboto', sans-serif;
            }
            @keyframes fadeIn {
                from {
                    opacity: 0;
                }
                to {
                    opacity: 1;
                }
            }
            @keyframes slideInRedLine {
                from {
                    left: 100%%;
                }
                to {
                    left: 0;
                }
            }
            @keyframes fillBackground {
                from {
                    background-color: rgba(50, 50, 50, 0);
                }
                to {
                    background-color: rgba(50, 50, 50, 0.05);
                }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="content">
                <div class="red-line"></div>
                <div class="text-wrapper">
                    <div class="text-content">
                        <h1>500</h1>
                        <h2>Internal Error</h2>
                    </div>
                </div>
            </div>
            <div class="disclaimer">
                You're request has failed.
            </div>
            <div class="info-compartment">
                ID: %s
            </div>
        </div>
    </body>
    </html>    

]]
_M.forbidden = [[
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>403 Forbidden</title>
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Roboto:wght@400;500&display=swap');
    
            body {
                font-family: 'Roboto', sans-serif;
                background-color: #ffffff;
                color: #333333;
                margin: 0;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                overflow: hidden;
            }
            .container {
                text-align: center;
                display: flex;
                flex-direction: column;
                align-items: center;
                animation: fadeIn 1s ease-in-out;
            }
            .content {
                display: flex;
                align-items: center;
                justify-content: center;
                position: relative;
                margin-bottom: 15px;
                padding: 6px 12px;
                background-color: rgba(0, 0, 0, 0);
                animation: fillBackground 2s ease-in-out forwards;
                animation-delay: 1s;
                width: 90%%;
                height: 80%%;
            }
            .red-line {
                position: absolute;
                height: 100%%;
                width: 3px;
                background-color: #B22222;
                left: 100%%;
                animation: slideInRedLine 1s ease-in-out forwards;
            }
            .text-wrapper {
                display: flex;
                align-items: center;
                padding: 0 8px;
                position: relative;
            }
            .text-content {
                display: flex;
                align-items: center;
                position: relative;
                z-index: 1;
            }
            .text-content h1 {
                font-size: 22.4px;
                margin: 0;
                font-weight: 500;
            }
            .text-content h2 {
                font-size: 22.4px;
                margin: 0;
                font-weight: 500;
                padding-left: 8px;
            }
            .info-compartment {
                font-size: 12.8px;
                color: #666666;
                border-top: 1px solid #e0e0e0;
                padding-top: 8px;
                font-family: 'Roboto', sans-serif;
            }
            .disclaimer {
                font-size: 12.8px;
                color: #666666;
                padding-bottom: 4px;
                font-family: 'Roboto', sans-serif;
            }
            @keyframes fadeIn {
                from {
                    opacity: 0;
                }
                to {
                    opacity: 1;
                }
            }
            @keyframes slideInRedLine {
                from {
                    left: 100%%;
                }
                to {
                    left: 0;
                }
            }
            @keyframes fillBackground {
                from {
                    background-color: rgba(50, 50, 50, 0);
                }
                to {
                    background-color: rgba(50, 50, 50, 0.05);
                }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="content">
                <div class="red-line"></div>
                <div class="text-wrapper">
                    <div class="text-content">
                        <h1>403</h1>
                        <h2>Forbidden</h2>
                    </div>
                </div>
            </div>
            <div class="disclaimer">
                %s
            </div>
            <div class="info-compartment">
                ID: %s
            </div>
        </div>
    </body>
    </html>    

]]
    
return _M