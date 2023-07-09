import esbuild from 'esbuild'
const minify = true

const esm = esbuild.build({
    bundle: true,
    minify: minify,
    entryPoints: ['./src/index.ts'],
    tsconfig: './tsconfig.esm.json',
    outdir: './dist',
    outExtension: {
        '.js': '.mjs',
    },
    platform: 'node',
    format: 'esm',
    target: 'es2022',
})

const cjs = esbuild.build({
    bundle: true,
    minify: minify,
    entryPoints: ['./src/index.ts'],
    tsconfig: './tsconfig.json',
    outdir: './dist',
    outExtension: {
        '.js': '.cjs',
    },
    platform: 'node',
    format: 'cjs',
    target: 'es2022',
})

Promise.all([esm, cjs])
