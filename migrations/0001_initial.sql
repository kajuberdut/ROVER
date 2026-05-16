--
-- PostgreSQL database dump
--

\restrict FyrMVjZbyPhqyJdRSkXVDXAQpAU3UVl12aya3kmCUfiWPorp6vCYmJZExhoWdHJ

-- Dumped from database version 17.10
-- Dumped by pg_dump version 17.10

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: api_tokens; Type: TABLE; Schema: public; Owner: rover
--

CREATE TABLE public.api_tokens (
    id character varying NOT NULL,
    user_sub character varying NOT NULL,
    name character varying NOT NULL,
    token_hash character varying NOT NULL,
    permission character varying NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    last_used_at timestamp without time zone
);


ALTER TABLE public.api_tokens OWNER TO rover;

--
-- Name: ci_image_metadata; Type: TABLE; Schema: public; Owner: rover
--

CREATE TABLE public.ci_image_metadata (
    image_hash character varying NOT NULL,
    repo_uri character varying NOT NULL,
    commit_hash character varying NOT NULL,
    metadata_json character varying DEFAULT '{}'::character varying,
    image_tags character varying DEFAULT '[]'::character varying,
    ci_job_url character varying,
    created_by_user_sub character varying,
    created_by_token_id character varying,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.ci_image_metadata OWNER TO rover;

--
-- Name: eol_cache; Type: TABLE; Schema: public; Owner: rover
--

CREATE TABLE public.eol_cache (
    id character varying NOT NULL,
    name character varying NOT NULL,
    version character varying NOT NULL,
    response_json character varying NOT NULL,
    cached_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.eol_cache OWNER TO rover;

--
-- Name: images; Type: TABLE; Schema: public; Owner: rover
--

CREATE TABLE public.images (
    id character varying NOT NULL,
    name character varying NOT NULL,
    image_hash character varying,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.images OWNER TO rover;

--
-- Name: major_components; Type: TABLE; Schema: public; Owner: rover
--

CREATE TABLE public.major_components (
    id character varying NOT NULL,
    name character varying NOT NULL,
    version character varying NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.major_components OWNER TO rover;

--
-- Name: product_users; Type: TABLE; Schema: public; Owner: rover
--

CREATE TABLE public.product_users (
    user_sub character varying NOT NULL,
    product_id character varying NOT NULL,
    role character varying NOT NULL
);


ALTER TABLE public.product_users OWNER TO rover;

--
-- Name: products; Type: TABLE; Schema: public; Owner: rover
--

CREATE TABLE public.products (
    id character varying NOT NULL,
    name character varying NOT NULL,
    description character varying DEFAULT ''::character varying,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.products OWNER TO rover;

--
-- Name: release_assets; Type: TABLE; Schema: public; Owner: rover
--

CREATE TABLE public.release_assets (
    id character varying NOT NULL,
    release_id character varying NOT NULL,
    asset_type character varying NOT NULL,
    asset_id character varying NOT NULL,
    git_ref character varying,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.release_assets OWNER TO rover;

--
-- Name: releases; Type: TABLE; Schema: public; Owner: rover
--

CREATE TABLE public.releases (
    id character varying NOT NULL,
    product_id character varying,
    name character varying NOT NULL,
    version character varying NOT NULL,
    is_end_of_life boolean DEFAULT false,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.releases OWNER TO rover;

--
-- Name: repositories; Type: TABLE; Schema: public; Owner: rover
--

CREATE TABLE public.repositories (
    id character varying NOT NULL,
    url character varying NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.repositories OWNER TO rover;

--
-- Name: scan_jobs; Type: TABLE; Schema: public; Owner: rover
--

CREATE TABLE public.scan_jobs (
    id character varying NOT NULL,
    target_url character varying NOT NULL,
    git_ref character varying,
    status character varying NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    results_json character varying,
    error_message character varying,
    resolved_commit character varying,
    resolved_tags character varying,
    target_type character varying DEFAULT 'repo'::character varying
);


ALTER TABLE public.scan_jobs OWNER TO rover;

--
-- Name: semgrep_jobs; Type: TABLE; Schema: public; Owner: rover
--

CREATE TABLE public.semgrep_jobs (
    id character varying NOT NULL,
    target_url character varying NOT NULL,
    git_ref character varying,
    resolved_commit character varying,
    status character varying NOT NULL,
    results_json character varying,
    resolved_tags character varying,
    error_message character varying,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.semgrep_jobs OWNER TO rover;

--
-- Name: users; Type: TABLE; Schema: public; Owner: rover
--

CREATE TABLE public.users (
    sub character varying NOT NULL,
    email character varying,
    name character varying,
    role character varying DEFAULT 'viewer'::character varying NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    last_login timestamp without time zone
);


ALTER TABLE public.users OWNER TO rover;

--
-- Name: api_tokens api_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: rover
--

ALTER TABLE ONLY public.api_tokens
    ADD CONSTRAINT api_tokens_pkey PRIMARY KEY (id);


--
-- Name: api_tokens api_tokens_token_hash_key; Type: CONSTRAINT; Schema: public; Owner: rover
--

ALTER TABLE ONLY public.api_tokens
    ADD CONSTRAINT api_tokens_token_hash_key UNIQUE (token_hash);


--
-- Name: ci_image_metadata ci_image_metadata_pkey; Type: CONSTRAINT; Schema: public; Owner: rover
--

ALTER TABLE ONLY public.ci_image_metadata
    ADD CONSTRAINT ci_image_metadata_pkey PRIMARY KEY (image_hash);


--
-- Name: eol_cache eol_cache_pkey; Type: CONSTRAINT; Schema: public; Owner: rover
--

ALTER TABLE ONLY public.eol_cache
    ADD CONSTRAINT eol_cache_pkey PRIMARY KEY (id);


--
-- Name: images images_name_key; Type: CONSTRAINT; Schema: public; Owner: rover
--

ALTER TABLE ONLY public.images
    ADD CONSTRAINT images_name_key UNIQUE (name);


--
-- Name: images images_pkey; Type: CONSTRAINT; Schema: public; Owner: rover
--

ALTER TABLE ONLY public.images
    ADD CONSTRAINT images_pkey PRIMARY KEY (id);


--
-- Name: major_components major_components_pkey; Type: CONSTRAINT; Schema: public; Owner: rover
--

ALTER TABLE ONLY public.major_components
    ADD CONSTRAINT major_components_pkey PRIMARY KEY (id);


--
-- Name: product_users product_users_pkey; Type: CONSTRAINT; Schema: public; Owner: rover
--

ALTER TABLE ONLY public.product_users
    ADD CONSTRAINT product_users_pkey PRIMARY KEY (user_sub, product_id);


--
-- Name: products products_name_key; Type: CONSTRAINT; Schema: public; Owner: rover
--

ALTER TABLE ONLY public.products
    ADD CONSTRAINT products_name_key UNIQUE (name);


--
-- Name: products products_pkey; Type: CONSTRAINT; Schema: public; Owner: rover
--

ALTER TABLE ONLY public.products
    ADD CONSTRAINT products_pkey PRIMARY KEY (id);


--
-- Name: release_assets release_assets_pkey; Type: CONSTRAINT; Schema: public; Owner: rover
--

ALTER TABLE ONLY public.release_assets
    ADD CONSTRAINT release_assets_pkey PRIMARY KEY (id);


--
-- Name: releases releases_pkey; Type: CONSTRAINT; Schema: public; Owner: rover
--

ALTER TABLE ONLY public.releases
    ADD CONSTRAINT releases_pkey PRIMARY KEY (id);


--
-- Name: repositories repositories_pkey; Type: CONSTRAINT; Schema: public; Owner: rover
--

ALTER TABLE ONLY public.repositories
    ADD CONSTRAINT repositories_pkey PRIMARY KEY (id);


--
-- Name: repositories repositories_url_key; Type: CONSTRAINT; Schema: public; Owner: rover
--

ALTER TABLE ONLY public.repositories
    ADD CONSTRAINT repositories_url_key UNIQUE (url);


--
-- Name: scan_jobs scan_jobs_pkey; Type: CONSTRAINT; Schema: public; Owner: rover
--

ALTER TABLE ONLY public.scan_jobs
    ADD CONSTRAINT scan_jobs_pkey PRIMARY KEY (id);


--
-- Name: semgrep_jobs semgrep_jobs_pkey; Type: CONSTRAINT; Schema: public; Owner: rover
--

ALTER TABLE ONLY public.semgrep_jobs
    ADD CONSTRAINT semgrep_jobs_pkey PRIMARY KEY (id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: rover
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (sub);


--
-- Name: sqlite_autoindex_eol_cache_1; Type: INDEX; Schema: public; Owner: rover
--

CREATE UNIQUE INDEX sqlite_autoindex_eol_cache_1 ON public.eol_cache USING btree (name, version);


--
-- Name: sqlite_autoindex_major_components_1; Type: INDEX; Schema: public; Owner: rover
--

CREATE UNIQUE INDEX sqlite_autoindex_major_components_1 ON public.major_components USING btree (name, version);


--
-- Name: sqlite_autoindex_releases_1; Type: INDEX; Schema: public; Owner: rover
--

CREATE UNIQUE INDEX sqlite_autoindex_releases_1 ON public.releases USING btree (name, version);


--
-- Name: api_tokens api_tokens_user_sub_fkey; Type: FK CONSTRAINT; Schema: public; Owner: rover
--

ALTER TABLE ONLY public.api_tokens
    ADD CONSTRAINT api_tokens_user_sub_fkey FOREIGN KEY (user_sub) REFERENCES public.users(sub) ON DELETE CASCADE;


--
-- Name: product_users product_users_product_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: rover
--

ALTER TABLE ONLY public.product_users
    ADD CONSTRAINT product_users_product_id_fkey FOREIGN KEY (product_id) REFERENCES public.products(id) ON DELETE CASCADE;


--
-- Name: product_users product_users_user_sub_fkey; Type: FK CONSTRAINT; Schema: public; Owner: rover
--

ALTER TABLE ONLY public.product_users
    ADD CONSTRAINT product_users_user_sub_fkey FOREIGN KEY (user_sub) REFERENCES public.users(sub) ON DELETE CASCADE;


--
-- Name: release_assets release_assets_release_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: rover
--

ALTER TABLE ONLY public.release_assets
    ADD CONSTRAINT release_assets_release_id_fkey FOREIGN KEY (release_id) REFERENCES public.releases(id);


--
-- PostgreSQL database dump complete
--

\unrestrict FyrMVjZbyPhqyJdRSkXVDXAQpAU3UVl12aya3kmCUfiWPorp6vCYmJZExhoWdHJ

